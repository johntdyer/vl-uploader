require 'spec_helper'
require 'prism.rb'


describe Prism, :type => 'library' do

    let(:ohai_data) do
        #Fauxhai.mock(:platform => "centos", :version=> "5.8").data#.merge!(
        { :platform => "centos", :platform_version => '5.3', :ipaddress => "1.2.3.4" }
    end

    let(:attr_ns) { 'prism' }

    before do
        FakeWeb.register_uri(:get, "http://ip.voxeolabs.net/", :body => '{"ip":"1.2.3.4"}',:content_type=>'application/json',:status=>["200","OK"])
        @node = Chef::Node.new
        @node.consume_external_attrs(Mash.new(ohai_data), {})
        @node.from_file(File.join(File.dirname(__FILE__), %w{.. .. attributes default.rb}))
    end

    after :each do
        FakeWeb.clean_registry
    end


    before(:all) do
        FakeWeb.allow_net_connect = false
        flexmock(Chef::Log).should_receive[:info].with_args("foo").and_return("foo")

        @scm_10_running  = <<-EOF
        <config version="1.0">
            <category name="SystemStatus">
                <item name="RestartPending">false</item>
                <category name="as">
                    <item name="DisplayName">Voxeo Prism Application Server</item>
                    <item name="Status">Running</item>
                    <item name="ProcessId">6360</item>
                </category>
                <category name="ms">
                    <item name="DisplayName">Voxeo Prism Media Server</item>
                    <item name="Status">Running</item>
                    <item name="ProcessId">5862</item>
                </category>
            </category>
        </config>
        EOF

       @scm_10_stopped  = <<-EOF
        <config version="1.0">
            <category name="SystemStatus">
                <item name="RestartPending">false</item>
                <category name="as">
                    <item name="DisplayName">Voxeo Prism Application Server</item>
                    <item name="Status">Stopped</item>
                    <item name="ProcessId">6360</item>
                </category>
                <category name="ms">
                    <item name="DisplayName">Voxeo Prism Media Server</item>
                    <item name="Status">Stopped</item>
                    <item name="ProcessId">5862</item>
                </category>
            </category>
        </config>
        EOF



        @version_current = <<-EOF
            <?xml version='1.0' encoding='UTF-8'?>
            <version>
                <msctrl>12.3.0.C201303011821.0</msctrl>
                <icon>trunk-55873</icon>
                <mrcp>12.3.0.C201303011821.0</mrcp>
                <grammartranslator>11.6-SNAPSHOT</grammartranslator>
                <mediaserver>11.7.70080</mediaserver>
                <vlib-gut>12.2.52</vlib-gut>
                <vlib-core>12.2.25</vlib-core>
                <prism>12.3.0.C201303011821.0_x64</prism>
            </version>
            EOF

        @version_old = <<-EOF
        <?xml version='1.0' encoding='UTF-8'?>
        <version>
            <msctrl>12.0.0.C201303011821.0</msctrl>
            <icon>trunk-55873</icon>
            <mrcp>12.0.0.C201303011821.0</mrcp>
            <grammartranslator>11.6-SNAPSHOT</grammartranslator>
            <mediaserver>11.7.70080</mediaserver>
            <vlib-gut>12.2.52</vlib-gut>
            <vlib-core>12.2.25</vlib-core>
            <prism>12.0.0.C201303011821.0_x64</prism>
        </version>
        EOF

      flexmock(Chef::Config).should_receive[:http_proxy].and_return(true)

    end

    describe ".build_throttling_config" do

        it "should handle a nil value" do
            Prism.build_throttling_config(@node).should eql ""
        end

        it "should be nil when threshold is nil" do

            @node.default['prism']['throttling']['type']      =  'caps'
            @node.default['prism']['throttling']['release']   =  20
            @node.default['prism']['throttling']['response']  =  503
            Prism.build_throttling_config(@node).should eql ""
        end

        it "should handle a release value" do

            @node.default['prism']['throttling']['type']      =  'caps'
            @node.default['prism']['throttling']['release']   =  20
            @node.default['prism']['throttling']['threshold'] =  20
            @node.default['prism']['throttling']['response']  =  503
            Prism.build_throttling_config(@node).should eql "<Throttling type='caps' threshold='20' release='20' response='503'/>\n"
        end

        it "should handle a when release value is missing" do

            @node.default['prism']['throttling']['type']      =  'caps'
            @node.default['prism']['throttling']['threshold'] =  20
            @node.default['prism']['throttling']['response']  =  503
            Prism.build_throttling_config(@node).should eql "<Throttling type='caps' threshold='20' response='503'/>\n"
        end
    end


    describe ".build_isc" do

        it "should not build ISC if empty, and this should be the default" do
            Prism.build_isc(@node['prism']['isc']).should eql(nil)
        end

        it "should build ISC without enum configuration" do

            @node.default['prism']['isc'] = {
                        'ioi' => 'test.com',
                        'routing_routes'    => [
                            "sip:172.21.99.222;lr"
                        ],
                        'initiating_routes' => [
                            "sip:1.2.3.4;lr"
                        ]
                    }

            Prism.build_isc(@node['prism']['isc']).should eql("<ISC ioi='test.com' >\n      <routing-routes>\n        <route uri='sip:172.21.99.222;lr'/>\n      </routing-routes>\n      <initiating-routes>\n        <route uri='sip:1.2.3.4;lr'/>\n      </initiating-routes>\n    </ISC>\n")
        end

        it "should build ISC with enum configuration" do

            @node.default['prism']['isc']  = {
                'ioi' => 'test.com',
                'route_policy_provider' => "com.micromethod.sipmethod.server.sip.impl.EnumRoutePolicy",
                'route_policy_provider_config' => "/opt/voxeo/prism/iscEnumPolicy.properties",
                'isc_enum_policy_properties' => [
                    {"prefixForLocalNumber"=>"+86"},
                    {"addLrParameter"=>true}
                ],
                'routing_routes'    => [
                    "sip:172.21.99.222;lr"
                ],
                'initiating_routes' => [
                    "sip:1.2.3.4;lr"
                ]
           }

            Prism.build_isc(@node['prism']['isc']).should eql("<ISC ioi='test.com' routePolicyProvider='com.micromethod.sipmethod.server.sip.impl.EnumRoutePolicy' routePolicyProviderConfig='/opt/voxeo/prism/iscEnumPolicy.properties' >\n      <routing-routes>\n        <route uri='sip:172.21.99.222;lr'/>\n      </routing-routes>\n      <initiating-routes>\n        <route uri='sip:1.2.3.4;lr'/>\n      </initiating-routes>\n    </ISC>\n")
        end
    end

    describe "build_secure_transports", fakefs: true do

        before(:each) do
            FileUtils.mkdir_p("/opt/voxeo/prism/conf")
        end

        before(:each) do
            Chef::Application.stub(:fatal!).and_raise(SystemExit)
        end

        it "should handle nil value by default" do
            Prism.build_secure_transports(@node).should eql ""
        end

        it "use http threadpool when https is nil" do
            File.open("/opt/voxeo/prism/conf/.keystore", "w") do |f|
                 f.puts("foo")
            end

            @node.default['prism']['keystore']['alias']        = "foo"
            @node.default['prism']['keystore']['keypass']      = "password"
            @node.default['prism']['keystore']['keystorepass'] = "password"

            Prism.build_secure_transports(@node).should eql "<NetworkAccessPoint port='8443' coreThreadPoolSize='50' transport='https'/>
<SecureTransport protocols='TLS' algorithm='SunX509' keystoreType='JKS' keystore='/opt/voxeo/prism/conf/.keystore' keystorepass='password' keypass='password' keyAlias='foo' />"
        end
    end

    describe ".build_enum_properties" do

        it "should handle a nil value" do
            Prism.build_enum_properties(@node).should eql ("")
        end

        it "should handle a valid config" do
            @node.default['prism']['isc'] = {
                'isc_enum_policy_properties' => [
                                {"prefixForLocalNumber"=>"+86"},
                                {"addLrParameter"=>true}
                            ]
                        }

            Prism.build_enum_properties(@node).should eql ("prefixForLocalNumber=+86\naddLrParameter=true")
        end
    end

    describe ".get_public_ipv4" do
        it "should get an ip address" do
            FakeWeb.register_uri(:get, "http://ip.voxeolabs.net/", :body => '{"ip":"1.2.3.4"}',:content_type=>'application/json',:status=>["200","OK"])
            Prism.get_public_ipv4.should == "1.2.3.4"
        end
    end

    describe ".build_jolokia_config" do

        it "should confirm values to correct XML" do
            @node.default['prism']['jolokia']['allowed'] =  [{
                                "name" => "java.lang:type=Memory",
                                "attribute" => "*Memory",
                                "operation" => "gc"
                            }]
            Prism.build_jolokia_config(@node["prism"]["jolokia"]["allowed"]).should eql "<mbean>\n    <name>java.lang:type=Memory</name>\n    <attribute>*Memory</attribute>\n    <operation>gc</operation>\n</mbean>"
        end

        it "should handle empty 'allowed' array" do
            @node.default['prism']['jolokia']['allowed_commands'] = [{}]
            Prism.build_jolokia_config(@node["prism"]["jolokia"]["allowed_commands"]).should eql "<mbean>\n</mbean>"
        end

        it "should handle empty 'denied' array" do
            @node.default['prism']['jolokia']['denied_commands'] = [{}]
            Prism.build_jolokia_config(@node["prism"]["jolokia"]["denied_commands"]).should eql "<mbean>\n</mbean>"
        end
    end

    describe ".build_nap" do
        before(:each) do
            flexmock(Chef::Log).should_receive[:info].with_args("foo").and_return("foo")
        end

        it "should add messageSize for TCP connector when it is missing when in nat_mode" do
            Prism.build_nap({
                'nat_mode'  => true,
                'relayAddress' => '8.8.8.8',
                'connector' => {
                    "transport"  =>  "tcp",
                    "port"       =>  5060
                }
            }).should eql "<NetworkAccessPoint messageSize='16384' relayPort='5060' relayAddress='8.8.8.8' transport='tcp' port='5060'/>"
        end

        it "should add address in nat mode if specified" do
            Prism.build_nap({
                'nat_mode'  => true,
                'relayAddress' => '8.8.8.8',
                'connector' => {
                    "address"    => '1.2.3.4',
                    "transport"  =>  "tcp",
                    "port"       =>  5060
                }
            }).should eql "<NetworkAccessPoint messageSize='16384' relayPort='5060' relayAddress='8.8.8.8' address='1.2.3.4' transport='tcp' port='5060'/>"
        end

        it "should not add address in nat mode if omited" do
            Prism.build_nap({
                'nat_mode'  => true,
                'relayAddress' => '8.8.8.8',
                'connector' => {
                    "transport"  =>  "tcp",
                    "port"       =>  5060
                }
            }).should eql "<NetworkAccessPoint messageSize='16384' relayPort='5060' relayAddress='8.8.8.8' transport='tcp' port='5060'/>"
        end

        it "should not add messageSize for UDP connector when it is missing when in nat_mode" do
            Prism.build_nap({
                'nat_mode'  => true,
                'address' => '1.2.3.4',
                'relayAddress' => '8.8.8.8',
                'connector' => {
                    "transport"  =>  "udp",
                    "port"       =>  5060
                }
            }).should eql "<NetworkAccessPoint relayPort='5060' relayAddress='8.8.8.8' transport='udp' port='5060'/>"
        end

        it "should add messageSize for TCP connector when it is missing" do
            Prism.build_nap({
                'connector' => {
                    "transport"  =>  "tcp",
                    "port"       =>  5060
                }
            }).should eql "<NetworkAccessPoint messageSize='16384' transport='tcp' port='5060'/>"
        end

        it "shouldn't add messageSize for UDP connector when it is missing" do
            Prism.build_nap({
                'connector' => {
                    "transport"  =>  "udp",
                    "port"       =>  5060
                }
            }).should eql "<NetworkAccessPoint transport='udp' port='5060'/>"
        end

        it "should correctly handle relayAddress and relayPort when passed in" do
            Prism.build_nap({
                'connector' => {
                    "transport"  =>  "udp",
                    "port"       =>  15060,
                    "relayPort"  =>  5060,
                    "address"    =>  "192.168.1.2",
                    "relayAddress" => "12.13.14.15"
                }
            }).should eql "<NetworkAccessPoint transport='udp' port='15060' relayPort='5060' address='192.168.1.2' relayAddress='12.13.14.15'/>"
        end
    end

    describe ".nap_address_helper" do

        it "should return 127.0.0.1 if nap doesnt have address" do
            @node.default['prism']['sipmethod']['access_points'] = [
                { "transport" => "udp", "port" => 5060 },
                { "transport" => "tcp", "port" => 5060 }
            ]

            Prism.nap_address_helper(@node['prism']['sipmethod']['access_points']).should eql "127.0.0.1"
        end

        it "should return 127.0.0.1 if TCP nap doesnt have and address, but UDP does" do
            @node.default['prism']['sipmethod']['access_points'] = [
                { "transport" => "udp", "port" => 5060 },
                { "transport" => "tcp", "port" => 5060 }
            ]

            Prism.nap_address_helper(@node['prism']['sipmethod']['access_points']).should eql "127.0.0.1"
        end

        it "should return tcp address if nap has one" do
            @node.default['prism']['sipmethod']['access_points'] = [
                    { "transport" => "tcp", "port" => 5060, 'address' => '1.2.3.4' },
                    { "transport" => "udp", "port" => 5060 }
            ]

            Prism.nap_address_helper(@node['prism']['sipmethod']['access_points']).should eql "1.2.3.4"
        end
    end

    describe ".nat_mapping" do

        it "should return nothing if not passed relay address" do
            Prism.nat_mapping(:relay_address=>nil).should == nil
        end

        it "should return correct mappings if passed relay_address and port" do
            opts = {:address=>'10.1.1.1', :relay_address=>'1.2.3.4', :port => 1234}
            Prism.nat_mapping(opts).should == "address='10.1.1.1' relayAddress='1.2.3.4' relayPort='1234'"
        end

        it "should return correct mappings if passed relay_address and relay_port" do
            opts = {:address=>'10.1.1.1', :relay_address=>'1.2.3.4', :relay_port => 1234, :port => 5555}
            Prism.nat_mapping(opts).should == "address='10.1.1.1' relayAddress='1.2.3.4' relayPort='1234' "
        end

        it "should not allow invalid relay port" do
            opts = {:address=>'10.1.1.1', :relay_address=>'1.2.3.4', :relay_port => 66666, :port => 5555}
            expect{ Prism.nat_mapping(opts) }.to raise_error
        end
    end

    describe ".mrcp_sessions" do

        before do
            @stats_10 = <<-EOF
                <counters>
                <item name='TTS/Licensed' type='int'>200</item>
                <item name='system/version/vcs'>10.0.54920.0</item>
                <item name='system/version/prism'>10.0.1.C201010230000.0_x64</item>
                <item name='system/starttime'>1323761233964512</item>
                <item name='MRCP/Sessions' type='int'>3</item>
                <item name='MRCP/Licensed' type='int'>200</item>
                <item name='CT/Licensed/Ports' type='int'>0</item>
                <item name='CT/Allocated/Ports' type='int'>0</item>
                <item name='CCXML/1.0/Sessions' type='int'>0</item>
                <item name='CallXML/Sessions' type='int'>0</item>
                <item name='ASR/Licensed' type='int'>200</item>
                </counters>
            EOF
        end

        it "should return zero when connection is refused" do
          FakeWeb.register_uri(:get, "http://1.2.3.4:10099/stats_10?type=cooked", :exception => Errno::ECONNREFUSED)
          Prism.mrcp_sessions('1.2.3.4').should == 0
        end

        it "should return zero when timeout is exceeded" do
          FakeWeb.register_uri(:get, "http://1.2.3.4:10099/stats_10?type=cooked", :exception => Timeout::Error)
          Prism.mrcp_sessions('1.2.3.4').should == 0
        end

        it "should return zero when host is down" do
          FakeWeb.register_uri(:get, "http://1.2.3.4:10099/stats_10?type=cooked", :exception => Errno::EHOSTDOWN)
          Prism.mrcp_sessions('1.2.3.4').should == 0
        end

        it "should return the correct session count" do
          FakeWeb.register_uri(:get, "http://1.2.3.4:10099/stats_10?type=cooked", :body => @stats_10,:status=>["200","OK"])
          Prism.mrcp_sessions("1.2.3.4").should == 3
        end

        it "should allow setting a port" do
          FakeWeb.register_uri(:get, "http://1.2.3.4:1234/stats_10?type=cooked", :body => @stats_10,:status=>["200","OK"])
          Prism.mrcp_sessions("1.2.3.4",1234).should == 3
        end
    end

    describe ".generate_md5_auth" do

        before(:each) do
            Chef::Application.stub(:fatal!).and_raise(SystemExit)
        end

        it "should return hash if all values are provided" do
            @node.default['prism']['vcs']['auth']['username'] = "foo"
            @node.default['prism']['vcs']['auth']['password'] = "foo"
            @node.default['prism']['vcs']['auth']['salt'] = "foo"
           Prism.generate_md5_auth(@node).should eql "216d7c020d0732def6775af81f6dc44f"
        end

        describe "handle all nil combinations" do

            it "should fail if nil password is provided" do
                @node.default['prism']['vcs']['auth']['username'] = "foo"
                @node.default['prism']['vcs']['auth']['password'] = nil
                @node.default['prism']['vcs']['auth']['salt'] = "foo"

                lambda {
                    Prism.generate_md5_auth(@node)
                }.should raise_error SystemExit
            end

            it "should fail if nil salt is provided" do
                @node.default['prism']['vcs']['auth']['username'] = "foo"
                @node.default['prism']['vcs']['auth']['password'] = "foo"
                @node.default['prism']['vcs']['auth']['salt'] = nil

                lambda {
                    Prism.generate_md5_auth(@node)
                }.should raise_error SystemExit
            end

            it "should fail if nil username is provided" do
                @node.default['prism']['vcs']['auth']['username'] = nil
                @node.default['prism']['vcs']['auth']['password'] = "foo"
                @node.default['prism']['vcs']['auth']['salt'] = "foo"

                lambda {
                    Prism.generate_md5_auth(@node)
                }.should raise_error SystemExit
            end

            it "should fail if nil username, salt, and password is provided" do

                @node.default['prism']['vcs']['auth']['username'] = nil
                @node.default['prism']['vcs']['auth']['password'] = nil
                @node.default['prism']['vcs']['auth']['salt'] = nil

                lambda {
                    Prism.generate_md5_auth(@node)
                }.should raise_error SystemExit
            end
        end
    end

    describe ".encrypt_if_needed" do

        before(:each) do
            Chef::Application.stub(:fatal!).and_raise(SystemExit)
        end

        it "should return value if no key is provided" do
          Prism.encrypt_if_needed("foo",@node['prism']['aeskey']).should eql "foo"
        end

        it "should fail if nil password is provided" do
            lambda {
                Prism.encrypt_if_needed(nil,"encryptiontest!!")
            }.should raise_error SystemExit
        end

        describe "should handle all valid encryption options" do
            it "should return encrypted value if 128 bit key is provided" do
                @node.default['prism']['aeskey'] = "encryptiontest!!"
                Prism.encrypt_if_needed("foo",@node['prism']['aeskey']).should eql "XfnQnP92GOD7wlM4Nj8ufg==\n"
            end

            it "should return encrypted value if 256 bit key is provided" do
                @node.default['prism']['aeskey'] = "encryptiontest!!12345678"
                Prism.encrypt_if_needed("foo",@node['prism']['aeskey']).should eql "vjhKzZqgPjIz8lBiC5OlSQ==\n"
            end

            it "should return encrypted value if 512 bit key is provided" do
                @node.default['prism']['aeskey'] = "encryptiontest!!1234567890123456"
                Prism.encrypt_if_needed("foo",@node['prism']['aeskey']).should eql "nci8YBvZnLNyTyI4+ZSStg==\n"
            end

            it "should fail if invalid bit key is provided" do
                lambda {
                    Prism.encrypt_if_needed("foo","1")
                }.should raise_error SystemExit
            end
        end
    end

    describe ".space_for_backup?" do
        before(:each) do
            subject { Object.new() }
        end

        it "#should recognize when we have enough space" do
            subject.should_receive(:`)
                .once.with("df -m /tmp")
                .and_return("Filesystem           1M-blocks      Used Available Use% Mounted on\n/dev/mapper/VolGroup00-LogVol00\n                          8680      3965      4268  49% /\n")
            Prism.space_for_backup?.should eql true
        end

        it "#should recognize when there is not enough space" do
            subject.should_receive(:`)
                .once.with("df -m /tmp")
                .and_return("Filesystem           1M-blocks      Used Available Use% Mounted on\n/dev/mapper/VolGroup00-LogVol00\n                          480      3965      4268  49% /\n")
            Prism.space_for_backup?.should eql false
        end

    end

    describe ".get_major_version_number" do

        it "shoud handle proper artifact URLs" do
            Prism.get_major_version_number("http://somewhere.com/prism-12.3.C20111111111.bin").should eql (12)
        end

        it "shoud handle improper artifact URLs" do
            Prism.get_major_version_number("http://somewhere.com/prism-trunk.C20111111111.bin").should eql (0)
        end

        it "shoud handle a test / latest artifact URLs" do
            Prism.get_major_version_number("http://somewhere.com/prism-latest.x64.bin").should eql (12)
        end
    end

    describe ".build_custom_logger_properties" do

        it "should return nothing when no properties are passed" do
            Prism.build_custom_logger_properties(@node).should eql ""
        end

        it "should return valid properties when properties are passed" do
            @node.default['prism']['log4j']['custom_properties'] =  ['foo=bar','foo2=bar2']
            Prism.build_custom_logger_properties(@node).should eql "foo=bar\nfoo2=bar2"
        end
    end

    describe ".installer_options" do

        it "should return sipoint and tropo when asked" do
            @node.default['prism']['bundled_apps'] = %w(SIPoint Tropo)
            Prism.installer_options(@node).should == '-DCONSOLE_PRISM_MODULES="SIPoint","Tropo"'
        end

        it "should return just sipoint when asked" do
            @node.default['prism']['bundled_apps'] = %w(SIPoint)
            Prism.installer_options(@node).should == '-DCONSOLE_PRISM_MODULES="SIPoint"'
        end

        it "should return just tropo when asked" do
            @node.default['prism']['bundled_apps'] = %w(Tropo)
            Prism.installer_options(@node).should == '-DCONSOLE_PRISM_MODULES="Tropo"'
        end

        it "should return neither when sipoint and tropo are not true, or nil" do
            Prism.installer_options(@node).should == '-DCONSOLE_PRISM_MODULES=\"NONE\"'
        end

        it "should return app server only when told" do
            @node.default['prism']['app_server_only'] = true
            Prism.installer_options(@node).should == '-DCONSOLE_PRISM_MODULES=\"NONE\" -DCONSOLE_INSTALL_TYPE=/"Application Server/"'
        end
    end

    describe ".build_servlet_network_access_point" do

        before(:each) do
            Chef::Application.stub(:fatal!).and_raise(SystemExit)
            @node.default['prism']['http_listen_address'] = "1.2.3.4"
        end

        it "should return nothing if nothing is passed in" do
            Prism.build_servlet_network_access_point(@node,nil,nil).should eql nil
        end

        it "should return nothing if http port and listen_address match" do
            Prism.build_servlet_network_access_point(@node,8080,"1.2.3.4").should eql nil
        end

        it "should return nothing if using Prism defaults ( server port is 8080 and address is nil )" do
            Prism.build_servlet_network_access_point(@node,8080,nil).should eql nil
        end

        it "should raise SystemExit if we try to specify alternate servlet address and prism['http_listen_address'] is nil" do
            @node.default['prism']['http_listen_address'] = nil

            lambda {
                Prism.build_servlet_network_access_point(@node,8080,"1.2.3.4")
            }.should raise_error SystemExit
        end

        it "should return only port as long as it's different then prism's http_port attribute" do
            Prism.build_servlet_network_access_point(@node,8081,nil).should eql "<NetworkAccessPoint transport='http' port='8081' />\n"
        end

        it "should return only port as long as it's different then prism's http_port attribute" do
            Prism.build_servlet_network_access_point(@node,8081,nil).should eql "<NetworkAccessPoint transport='http' port='8081' />\n"
        end
        it "should return port and address provided listen_address does not match prism's http_listen_address" do
            Prism.build_servlet_network_access_point(@node,8081,"1.2.3.5").should eql "<NetworkAccessPoint transport='http' address='1.2.3.5' port='8081' />\n"
        end

        it "should return port and address provided port does not match prism's http_port" do
            Prism.build_servlet_network_access_point(@node,8081,"1.2.3.4").should eql "<NetworkAccessPoint transport='http' address='1.2.3.4' port='8081' />\n"
        end

    end

    describe ".app_server_running?" do

        it "should return false when connection is refused" do
          FakeWeb.register_uri(:get, "http://1.2.3.4:10086/scm_10?action=status", :exception => Errno::ECONNREFUSED)
          Prism.app_server_running?('1.2.3.4').should eql false
        end

        it "should return true when app server is running" do
          FakeWeb.register_uri(:get, "http://1.2.3.4:10086/scm_10?action=status", :body => @scm_10_running,:status=>["200","OK"])
          Prism.app_server_running?('1.2.3.4').should eql true
        end

        it "should return false when app server is stopped" do
          FakeWeb.register_uri(:get, "http://1.2.3.4:10086/scm_10?action=status", :body => @scm_10_stopped,:status=>["200","OK"])
          Prism.app_server_running?('1.2.3.4').should eql false
        end
    end

    describe ".media_server_running?" do

        it "should return false when connection is refused" do
          FakeWeb.register_uri(:get, "http://1.2.3.4:10086/scm_10?action=status", :exception => Errno::ECONNREFUSED)
          Prism.media_server_running?('1.2.3.4').should eql false
        end

        it "should return true when media server is running" do
          FakeWeb.register_uri(:get, "http://1.2.3.4:10086/scm_10?action=status", :body => @scm_10_running,:status=>["200","OK"])
          Prism.media_server_running?('1.2.3.4').should eql true
        end

        it "should return false when media server is stopped" do
          FakeWeb.register_uri(:get, "http://1.2.3.4:10086/scm_10?action=status", :body => @scm_10_stopped,:status=>["200","OK"])
          Prism.media_server_running?('1.2.3.4').should eql false
        end
    end

    describe ".installed?", fakefs: true do

        before(:each) do
            FileUtils.mkdir_p(@node['prism']['path']['prism']+"/conf")
        end

        it "should detect when Prism is installed" do
            Prism.installed?(@node).should eql true
        end

        it "should detect when Prism is not installed" do
            @node.override['prism']['path']['prism'] = "/a/path/which/doesnt/exists"
            Prism.installed?(@node).should be(false)
        end
    end

    describe ".install_will_be_upgrade?", fakefs: true do

        before(:each) do
            FileUtils.mkdir_p("/opt/voxeo/prism/conf")
        end

        it "should recognize matching version number from URL" do

            default_version = @node['prism']['artifacts']['url']
                                .split("/")[-1]
                                .gsub(".bin","")
                                .gsub("prism-","")
                                .gsub("_",".")
                                .gsub("-","_")

            @version_current = <<-EOF
            <?xml version='1.0' encoding='UTF-8'?>
            <version>
                <msctrl>12.3.0.C201303011821.0</msctrl>
                <icon>trunk-55873</icon>
                <mrcp>12.3.0.C201303011821.0</mrcp>
                <grammartranslator>11.6-SNAPSHOT</grammartranslator>
                <mediaserver>11.7.70080</mediaserver>
                <vlib-gut>12.2.52</vlib-gut>
                <vlib-core>12.2.25</vlib-core>
                <prism>#{default_version}</prism>
            </version>
            EOF

            File.open("/opt/voxeo/prism/conf/version.xml", "w") do |f|
                f.puts(@version_current)
            end

            Prism.install_will_be_upgrade?(@node).should eql false
        end

        it "should recognize NON matching version number from URL" do

            File.open("/opt/voxeo/prism/conf/version.xml", "w") do |f|
                 f.puts(@version_current)
            end
            @node.override['prism']['artifacts']['url'] =  "http://somewhere.com/prism-11_0_0_C201303011821_0-x64.bin"

            Prism.install_will_be_upgrade?(@node).should eql true
        end

        it "should recognize matching version number from File" do
            File.open("/opt/voxeo/prism/conf/version.xml", "w") do |f|
                 f.puts(@version_old)
            end

            @node.override['prism']['artifacts']['url'] =  "http://somewhere.com/prism-12_0_0_C201303011821_0-x64.bin"

            Prism.install_will_be_upgrade?(@node).should eql false
        end

        it "should recognize NON matching version number from URL" do
            File.open("/opt/voxeo/prism/conf/version.xml", "w") do |f|
                 f.puts(@version_old)
            end
            Prism.install_will_be_upgrade?(@node).should eql true
        end

    end

    describe ".install_necessary?", fakefs: true do

        before(:each) do
            default_version = @node['prism']['artifacts']['url']
                                .split("/")[-1]
                                .gsub(".bin","")
                                .gsub("prism-","")
                                .gsub("_",".")
                                .gsub("-","_")

            @version_current = <<-EOF
            <?xml version='1.0' encoding='UTF-8'?>
            <version>
                <msctrl>12.3.0.C201303011821.0</msctrl>
                <icon>trunk-55873</icon>
                <mrcp>12.3.0.C201303011821.0</mrcp>
                <grammartranslator>11.6-SNAPSHOT</grammartranslator>
                <mediaserver>11.7.70080</mediaserver>
                <vlib-gut>12.2.52</vlib-gut>
                <vlib-core>12.2.25</vlib-core>
                <prism>#{default_version}</prism>
            </version>
            EOF
        end
        it "should recognize when there is Prism directory" do
            FileUtils.mkdir_p("/opt/voxeo/prism/conf")
            File.open("/opt/voxeo/prism/conf/version.xml", "w") do |f|
                f.puts(@version_current)
            end

            Prism.install_necessary?(@node).should eql false
        end

        it "should recognize when there is a Prism directory but no version.xml" do
            pending "I dont think this is correct"
            FileUtils.mkdir_p("/opt/voxeo/prism/conf")
            #(File.methods - Object.methods).should eql 1
            #(FileUtils.methods - Object.methods).should eql 1
            #File.exists?("/opt/voxeo/prism/conf/version.xml").should eql false
            Prism.install_necessary?(@node).should eql true
        end

        it "should recognize when there is no a Prism directory" do
            Prism.install_necessary?(@node).should eql true
        end

    end

    describe ".backup_exclusions" do
        Prism.backup_exclusions.should == "--exclude='apps/PrismDemoApp*' --exclude='server/apps/com.voxeo.directory*' --exclude='server/apps/com.voxeo.prism.callrouter*' --exclude='server/apps/com.voxeo.prism.ext*' --exclude='server/apps/com.voxeo.prism.msctrl*' --exclude='server/apps/console*' --exclude='server/apps/jolokia*'"
    end

    describe ".backup_file_exists?", fakefs: true do
        it "should recognize when a backup file exists" do
            FileUtils.mkdir_p("/tmp")
            File.open("/tmp/_prism-backup.tar", "w") do |f|
                f.puts("foo")
            end
            Prism.backup_file_exists?.should eql true
        end

        it "should recognize when a backup file does not exists" do
            FileUtils.mkdir_p("/tmp")
            Prism.backup_file_exists?.should eql false
        end

    end

    describe ".do_backup?", fakefs: true do

        it "should return false when backup already exists" do
            FileUtils.mkdir_p("/tmp")
            File.open("/tmp/_prism-backup.tar", "w") do |f|
                f.puts("foo")
            end

            Prism.do_backup?(@node).should eql false
        end

        it "should return true when backup file doesnt exist, an upgrade is necessary, and we have enough space" do
            subject { Object.new() }

            FileUtils.mkdir_p("/opt/voxeo/prism/conf/")
            # File.open("/tmp/_prism-backup.tar", "w") do |f|
            #     f.puts("foo")
            # end
            File.open("/opt/voxeo/prism/conf/version.xml", "w") do |f|
                 f.puts(@version_old)
            end

            subject.should_receive(:`)
                .once.with("df -m /tmp")
                .and_return("Filesystem           1M-blocks      Used Available Use% Mounted on\n/dev/mapper/VolGroup00-LogVol00\n                          8680      3965      4268  49% /\n")


            Prism.do_backup?(@node).should eql true
        end

        it "should return false when backup file doesnt exist, an upgrade is necessary, and we dont have enough space" do
            subject { Object.new() }

            FileUtils.mkdir_p("/opt/voxeo/prism/conf/")
            File.open("/opt/voxeo/prism/conf/version.xml", "w") do |f|
                 f.puts(@version_old)
            end

            subject.should_receive(:`)
                .once.with("df -m /tmp")
                .and_return("Filesystem           1M-blocks      Used Available Use% Mounted on\n/dev/mapper/VolGroup00-LogVol00\n                          480      3965      4268  49% /\n")


            Prism.do_backup?(@node).should eql false
        end

        it "should return false when backup file doesnt exist and upgrade is necessary" do
            FileUtils.mkdir_p("/tmp")
            File.open("/tmp/_prism-backup.tar", "w") do |f|
                f.puts("foo")
            end
            Prism.do_backup?(@node_currect).should eql false
        end
    end

    describe ".list_asr_engines" do
        it "should handle no ASR engines" do
            @node.override['prism']['asr_engines'] = []
            Prism.list_asr_engines(@node['prism']['asr_engines']).should eql "dtmf=vxsredtmf"
        end

        it "should handle ASR engines" do
            Prism.list_asr_engines(@node['prism']['asr_engines']).should eql "dtmf=vxsredtmf, en-us=vxsrepr"
        end
    end

    describe ".only_on_box_tts_engines" do
        it "should handle no TTS engines" do
            @node.default['prism']['tts_engines'] = false
            Prism.only_on_box_tts_engines([]).should eql []
        end

        it "should handle TTS engines" do
            Prism.only_on_box_tts_engines(@node['prism']['tts_engines']).should eql [{"lang"=>"English-SAPI", "name"=>"English-Female4"}, {"lang"=>"en-us", "name"=>"English-Female4"}]
        end
    end

    describe ".only_off_box_tts_engines" do
        it "should handle no TTS engines" do
            Prism.only_off_box_tts_engines(@node['prism']['tts_engines']).should eql []
        end

        it "should handle TTS engines" do
            @node.default['prism']['tts_engines'] = [
                    {
                      "name"  => "susan","lang"  => "en-us","servers" => ["rtsp://172.25.163.103:5554/speechsynthesizer"]
                    }
                ]
            Prism.only_off_box_tts_engines(@node['prism']['tts_engines']).should eql [{"name"=>"susan", "lang"=>"en-us", "servers"=>["rtsp://172.25.163.103:5554/speechsynthesizer"]}]
        end
    end

    describe ".list_tts_engines" do
        it "should handle no TTS engines" do
            @node.override['prism']['tts_engines'] = []
            Prism.list_tts_engines(@node['prism']['tts_engines']).should eql ""
        end

        it "should handle TTS engines" do
            Prism.list_tts_engines(@node['prism']['tts_engines']).should eql "en-us=English-Female4, English-SAPI=English-Female4"
        end
    end

    describe ".grammar_translators" do
        it "should handle no asr engines" do
            @node.override['prism']['tts_engines'] = []
            Prism.grammar_translators(@node['prism']['tts_engines']).should eql ""
        end

        it "should handle asr engines" do
            @node.default['prism']['asr_engines'] = [
                    {
                        'lang' =>  "en-us",
                        'engine'  =>  "vxsrepr",
                        'grammar_translator' => "prophecy"
                    },
                    {
                        'ignore_cseq_errors' => true,
                        'engine' => 'vxsremrcp',
                        'translate_grammars' => false,
                        'lang' => 'en-us',
                        'grammar_translator' => 'loquendo',
                        'servers' =>['rtsp://172.16.163.103:5554/recognizer','rtsp://172.16.163.102:5554/recognizer']
                    }
                ]
            Prism.grammar_translators(@node['prism']['asr_engines']).should eql "        <Translate-Grammars>\n          <Attribute name=\"en-us\">false</Attribute>\n        </Translate-Grammars>"
        end
    end

    describe ".build_grammar_config" do
        it "should handle no asr engines" do
            @node.default['prism']['asr_engines'] = []
            Prism.build_grammar_config(@node['prism']['asr_engines']).should eql ""
        end

        it "should handle asr engines" do
            Prism.build_grammar_config(@node['prism']['asr_engines']).should eql "        <Langs>\n          <Attribute name=\"en-us\">prophecy</Attribute>\n        </Langs>"
        end
    end

    describe ".build_prism_asr_config" do

        it "should handle no asr engines" do
            @node.override['prism']['asr_engines'] = []
            Prism.build_prism_asr_config(@node['prism']['asr_engines']).should eql "<ASR>\n\n\n      </ASR>"
        end

        it "should handle array of asr engines" do
            @node.default['prism']['asr_engines'] = [
                    {
                        'lang' =>  "en-us",
                        'engine'  =>  "vxsrepr",
                        'grammar_translator' => "prophecy"
                    },
                    {
                        'ignore_cseq_errors' => true,
                        'engine' => 'vxsremrcp',
                        'translate_grammars' => false,
                        'lang' => 'en-us',
                        'grammar_translator' => 'loquendo',
                        'servers' =>['rtsp://172.16.163.103:5554/recognizer','rtsp://172.16.163.102:5554/recognizer']
                    }
                ]
            Prism.build_prism_asr_config(@node['prism']['asr_engines']).should eql "<ASR>\n        <Langs>\n          <Attribute name=\"en-us\">loquendo</Attribute>\n        </Langs>\n        <Translate-Grammars>\n          <Attribute name=\"en-us\">false</Attribute>\n        </Translate-Grammars>\n      </ASR>"
        end

    end

    describe ".build_tts_failover_groups" do

        it "should return a failover group wth one hosts" do
            Prism.build_tts_failover_groups([['English-Female4']],'linux').should eql "<item name='FailoverGroup1' platform='linux'>English-Female4</item>"
        end
        it "should return a failover group wth two hosts" do
            Prism.build_tts_failover_groups([['English-Female4','allison']],'linux').should eql "<item name='FailoverGroup1' platform='linux'>English-Female4,allison</item>"
        end

        it "should return a failover group wth no hosts" do
            Prism.build_tts_failover_groups([],'linux').should eql ""
        end

    end

    describe ".build_vcs_asr_config" do

        it "should handle no asr engines" do
            @node.override['prism']['asr_engines'] = []
            Prism.build_vcs_asr_config(@node['prism']['asr_engines']).should eql ""
        end

        it "should handle array of asr engines" do
            @node.default['prism']['asr_engines'] = [
                    {
                        'lang' =>  "en-us",
                        'engine'  =>  "vxsrepr",
                        'grammar_translator' => "prophecy"
                    },
                    {
                        'ignore_cseq_errors' => true,
                        'engine' => 'vxsremrcp',
                        'translate_grammars' => false,
                        'lang' => 'en-us',
                        'grammar_translator' => 'loquendo',
                        'servers' =>['rtsp://172.16.163.103:5554/recognizer','rtsp://172.16.163.102:5554/recognizer']
                    }
                ]
            Prism.build_vcs_asr_config(@node['prism']['asr_engines']).should eql "\t<category name='en-us'>\n\t  <item name='Servers'>rtsp://172.16.163.103:5554/recognizer,rtsp://172.16.163.102:5554/recognizer</item>\n\t  <item name='IgnoreCSeqErrors' type='int'>1</item>\n\t</category>"
        end

    end

    describe ".build_cluster_config" do
        it "should handle nil masters with username and password" do
            @node.default['prism']['aeskey'] = "1234567890123456"
            @node.default['prism']['pdd']['password'] = "foo"
            @node.default['prism']['pdd']['username'] = "foo"
            @node.default['prism']['pdd']['realm']    =  "ProvisioningRealm"

            Prism.build_cluster_config(@node).should eql "<Directory maxRetryTimes='5' maxConnectionSize='100' credentials='foo:Y65rLF3fzNfJ/0dh2sMYgg==' />"
        end

        it "should handle nil masters" do
            Prism.build_cluster_config(@node).should eql "<Directory maxRetryTimes='5' maxConnectionSize='100'  />"
        end

        it "shoudl handle 2 masters" do
            pending "Need to get Fauxhi working"

            @node['prism']['cluster']['masters'] =  ['1.2.3.4','4.5.6.7']

            Prism.build_cluster_config(node).should eql ""
        end
    end

    describe ".build_media_control_config" do

        it "should do nothing when no aeskey is defined" do
            Prism.build_media_control_config(@node).should eql "<MS uri='mrcp://1.2.3.4:10074' useLoopBackAddress='false'>\n<ASR>\n        <Langs>\n          <Attribute name=\"en-us\">prophecy</Attribute>\n        </Langs>\n\n      </ASR>\t</MS>"
        end

        it "should add username,password, and SCM port when aeskey is defined" do
            @node['prism']['aeskey'] = "1234567890123456"
            Prism.build_media_control_config(@node).should eql "<MS uri='mrcp://1.2.3.4:10074/?credentials=vcs:MTdrmlqLvmqmZUhmUYtLmQ==&amp;ctrlport=10099' useLoopBackAddress='false'>\n<ASR>\n        <Langs>\n          <Attribute name=\"en-us\">prophecy</Attribute>\n        </Langs>\n\n      </ASR>\t</MS>"
        end
    end

    describe ".requires_glibc_patch" do
        before(:each) do
            subject { Object.new() }
        end

        it "should handle when no rpm is installed" do
            pending "This doesnt work properly"
            Prism.requires_glibc_patch('x86_64').should eql false
        end

        it "should handle an version of glib < 2.5" do
            pending "Is this still necessary ? "
            subject.should_receive(:`)
                .once.with("rpm -qa | grep 'glibc-2.1' | grep x86_64")
                .and_return("glibc-2.3.2-11.9.src.rpm")

            Prism.requires_glibc_patch('x86_64').should eql true
        end
    end

    describe ".get_ip_addresses" do

        it "should return a valid ip address" do
            pending "Fauxhai sucks"
            Fauxhai.mock(platform:'centos', version:'5.8') do |node|
            end

            Prism.get_ip_addresses(@node).should eql "1.2.3.4"
        end

    end
end
