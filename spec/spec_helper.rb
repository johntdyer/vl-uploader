%w(
bundler/setup
flexmock/rspec
fakeweb
fauxhai
fakefs/spec_helpers
logger
json
chefspec
json_spec
guard/rspec
time
j_unit
chef/application
timecop
simplecov
chef/node
chef/platform
).each{|lib| require lib}

SimpleCov.start

FakeWeb.allow_net_connect = false

$:.push File.dirname(__FILE__) + "/../lib"

RSpec.configure do |config|
    config.filter_run :focus => true
    config.mock_with :flexmock
    config.run_all_when_everything_filtered = true
    config.color_enabled = true
    config.mock_with :rspec
    config.include FakeFS::SpecHelpers, fakefs: true
end
