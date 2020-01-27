#!/usr/bin/perl

use strict;
use warnings;

use XML::LibXML;
use Net::IP;
#################################### Const variables ################################

use constant FROX_CONF_WASP    => "/var/wasp/conf/FTP_EXT/current/module.xml";
use constant FROX_CONF         => "/etc/frox.conf";
use constant FROX_CONF_DEFAULT => "/etc/frox.conf.default";
use constant FROX_EXE          => "/usr/sbin/frox";

use constant OK => 0;
use constant ERROR => 1;

#####################################################################################

#####################################################################################
#                                    Main
#####################################################################################

my %configHash;

if ( parseConfigFile(\%configHash) != OK )
{
    writeLog( "[error] Failed to parse config file, starting with default configuration." );

    if ( configFroxDefault() != OK )
    {
        writeLog( "[error] Failed configure frox with default configuration, can't start frox. " );
        exit(1);
    }
}
elsif ( configFrox(\%configHash) != OK )
{
    writeLog( "[error] Failed to config frox, starting with default configuration." );

    if ( configFroxDefault() != OK )
    {
      writeLog( "[error] Failed configure frox with default configuration, can't start frox. " );
      exit(1);
    }
}

exit(0);

#####################################################################################
#                                  Functions
#####################################################################################
sub writeLog
{
  my ($str) = @_;

  print "Frox - $str\n";
}

sub configFroxDefault
{
    my $froxDefaultConf = FROX_CONF_DEFAULT;
    my $froxConf        = FROX_CONF;

    writeLog("[info] Config frox with defaults ... ");

    if ( system("cp $froxDefaultConf $froxConf") != 0 )
    {
        writeLog( "[error] Failed to restore frox default configuration." );
        return ERROR;
    }

    return OK;
}

sub configFrox
{
    my ($configHashRef) = @_;

    writeLog("[info] Configure frox ... ");
    #
    # bind ip 4- 'ListenIPv4 0.0.0.0'
    #

    my $ip4 = $$configHashRef{'ip'};
    if (not defined $ip4){
      $ip4 = "0.0.0.0";
    }
    my $ip6 = $$configHashRef{'ip6'};
    if (not defined $ip6){
      $ip6 = "::0";
    }
    my $is_ipv6 = `cat /etc/finjan/ipv6`;
    writeLog( "[info] ipv6 support: $is_ipv6");
    return ERROR if ( setConfigParam('^.*ListenIPv4 .*', "ListenIPv4 $ip4") != OK );
    if ( $is_ipv6 == "1" )
    {
        writeLog("[info] 2 listeners");
        return ERROR if ( setConfigParam('^Listeners \d+\$', "Listeners 2") != OK );
        return ERROR if ( setConfigParam('.*ListenIPv6 .*', "ListenIPv6 $ip6") != OK );
    } else {
        writeLog("[info] 1 listener");
	return ERROR if ( setConfigParam('^Listeners \d+\$', "Listeners 1") != OK );
        return ERROR if ( setConfigParam('^.*ListenIPv6 .*', "#ListenIPv6 $ip6") != OK );
    }

    #
    # bind port - 'Port 2121'
    #
    my $bindPort = $$configHashRef{'port'};
    if ( defined $bindPort )
    {
      if ( $bindPort eq "" or
           $bindPort < 1 or
           $bindPort > 65535 )
      {
        writeLog( "[error] Invalid listen port: '$bindPort'" );
        return ERROR;
      }

      return ERROR if ( setConfigParam('^Port \d+\$', "Port $bindPort") != OK );
    }

    #
    # ftp log level - 'LogLevel 15'
    #
    my $logLevel = $$configHashRef{'ftp-log-level'};
    if ( defined $logLevel )
    {
      if ( $logLevel eq "" or
           $logLevel < 0 or
           $logLevel > 25 )
      {
        writeLog( "[error] Invalid log level: '$logLevel'" );
        return ERROR;
      }

      return ERROR if ( setConfigParam('^LogLevel \d+\$', "LogLevel $logLevel") != OK );
    }

    #
    # next proxy
    # 'FTPProxy 192.168.2.9:2222'
    # 'FTPProxyNoPort yes'
    #
    my $enableNextProxy = $$configHashRef{'enable-next-proxy'};
    if ( defined $enableNextProxy )
    {
      if ( $enableNextProxy eq "" or
           ($enableNextProxy != 0 and $enableNextProxy != 1) )
      {
        writeLog( "[error] Invalid enable next proxy flag: '$enableNextProxy'" );
        return ERROR;
      }

      # enable next proxy
      if ( $enableNextProxy == 1 )
      {
        my $nextProxyIP = $$configHashRef{'next-proxy-ip'};
        my $nextProxyPort = $$configHashRef{'next-proxy-port'};

        if (defined $nextProxyPort )
        {
            if ( $nextProxyPort < 0 or $nextProxyPort > 65535 )
            {
                writeLog( "[error] invalid range for next proxy port: '$nextProxyPort'" );
                return ERROR;
            }
            my $addressFamily = Net::IP::ip_get_version($nextProxyIP);
            if ( $addressFamily != 4 and $addressFamily != 6)
            {
                writeLog( "[error] next proxy ip address coult not be determined: $addressFamily" );
                return ERROR;
            }
            if( $addressFamily == 4 ){
                return ERROR if ( setConfigParam('.*FTPProxy \d+\.\d+\.\d+\.\d+:\d+', "FTPProxy $nextProxyIP:$nextProxyPort") != OK );
            }elsif( $addressFamily == 6 ) {
                return ERROR if ( setConfigParam('.*FTPProxy .*', "FTPProxy $nextProxyIP") != OK );
            }
            return ERROR if ( setConfigParam('.*FTPProxyNoPort yes\$', "FTPProxyNoPort yes") != OK );
        }
        else
        {
            writeLog( "[error] Missing next proxy parameters while it is enabled." );
            return ERROR;
        }
      }
      # disable next proxy
      else
      {
        return ERROR if ( setConfigParam('.*FTPProxy \d+\.\d+\.\d+\.\d+:\d+', "#FTPProxy 0.0.0.0:2222") != OK );
        return ERROR if ( setConfigParam('.*FTPProxyNoPort yes\$', "#FTPProxyNoPort yes") != OK );
      }
    }

    #
    # Set an Access Control List
    #
    my $allowedPorts = $$configHashRef{'allowed-ports'};
    if ( defined $allowedPorts )
    {
       return ERROR if ( setConfigParam('^ACL Allow \* - \*.*\$', "ACL Allow \* - \* $allowedPorts") != OK );
       setConfigParam('# # You don\'t really believe in this security stuff, and just want',
                 "# # Allow access to connections that their destination port is on the list.");
       setConfigParam('# # everything to work.',
                 "# # The IP Control list will be managed by the SecurityAgent.");
    }

    my $a2pConv = $$configHashRef{'a2p'};
    if (defined $a2pConv)
    {
        return ERROR if (setConfigParam('^.*APConv .*\$', "APConv $a2pConv") != OK);
    }

    my $p2aConv = $$configHashRef{'p2a'};
    if (defined $p2aConv)
    {
        return ERROR if (setConfigParam('^.*PAConv .*\$', "PAConv $p2aConv") != OK);
    }


    return OK;
}

sub setConfigParam
{
  my ($oldParam, $newParam) = @_;
  my $froxConf = FROX_CONF;

  if ( system("perl -pi -e \"s/$oldParam/$newParam/\" $froxConf") != 0 )
  {
    writeLog( "[error] Failed to set parameter, OLD=>'$oldParam', NEW=>'$newParam'" );
    return ERROR;
  }

  return OK;
}


sub parseConfigFile
{
    my ($hashRef) = @_;

    writeLog( "[info] Parsing FTP configuration file: " . FROX_CONF_WASP );

    my $parser  = XML::LibXML->new();
    my $rootElement = undef;
    eval
    {
        $rootElement = $parser->parse_file(FROX_CONF_WASP)->getDocumentElement();
    };

    if ($@ or not defined $rootElement)
    {
        writeLog( "[info] Parse error in: " . FROX_CONF_WASP );
        return ERROR;
    }

    # init
    my $initList = ($rootElement->getChildrenByTagName("init"))[0];
    if ( not defined $initList )
    {
        writeLog("[error] Can't find 'init' element.");
        return ERROR;
    }

    # ip
    my $ipElement4 = ($initList->getChildrenByTagName("ip"))[0];
    $$hashRef{'ip'} = $ipElement4->getAttributeNode("value")->value();

    # ip
    my $ipElement6 = ($initList->getChildrenByTagName("ip6"))[0];
    $$hashRef{'ip6'} = $ipElement6->getAttributeNode("value")->value();

    # Listen port
    my $portElement = ($initList->getChildrenByTagName("port"))[0];
    $$hashRef{'port'} = $portElement->getAttributeNode("value")->value();

    # Allowed servers ports
    my $allowedPortElement = ($initList->getChildrenByTagName("AllowedPort"))[0];
    my @allowedPorts = $allowedPortElement->getChildrenByTagName("PortRange");

    my $portRange="";
    foreach my $FTPServerPort (@allowedPorts)
    {
       my $fromPort = $FTPServerPort->getAttributeNode("from")->value();
       my $toPort   = $FTPServerPort->getAttributeNode("to")->value();

       for(my $port = $fromPort; $port <= $toPort; $port++)
       {
          if( ! $portRange )
          {
             # first port in loop
             $portRange = $port;
          }
          else
          {
             $portRange = $portRange . ',' . $port;
          }
       }
    }
    $$hashRef{'allowed-ports'} =  $portRange;

    # ftp-log
    my $ftplogElement = ($initList->getChildrenByTagName("ftp-log"))[0];
#    $$hashRef{'ftp-log-fname'} = $ftplogElement->getAttributeNode("fname")->value();
    $$hashRef{'ftp-log-level'} = $ftplogElement->getAttributeNode("level")->value();

    # enable-next-proxy
    my $enableNextProxyElement = ($initList->getChildrenByTagName("enable-next-proxy"))[0];
    $$hashRef{'enable-next-proxy'} = $enableNextProxyElement->getAttributeNode("value")->value();

    # next-proxy-ip
    my $nextProxyIPElement = ($initList->getChildrenByTagName("next-proxy-ip"))[0];
    $$hashRef{'next-proxy-ip'} = $nextProxyIPElement->getAttributeNode("value")->value();

    # next-proxy-port
    my $nextProxyPortElement = ($initList->getChildrenByTagName("next-proxy-port"))[0];
    $$hashRef{'next-proxy-port'} = $nextProxyPortElement->getAttributeNode("value")->value();

    my $a2pElement = ($initList->getChildrenByTagName("APConv"))[0];
    $$hashRef{'a2p'} = (defined $a2pElement) ? $a2pElement->getAttributeNode("value")->value() : 'yes';

    my $p2aElement = ($initList->getChildrenByTagName("PAConv"))[0];
    $$hashRef{'p2a'} = (defined $p2aElement) ? $p2aElement->getAttributeNode("value")->value() : 'no';

    return OK;
}


