require 'spec_helper'
require 'uploader.rb'


describe uploader do

    let(:attr_ns) { 'prism' }

    before do
        FakeWeb.register_uri(:get, "http://ip.voxeolabs.net/", :body => '{"ip":"1.2.3.4"}',:content_type=>'application/json',:status=>["200","OK"])
    end

    after :each do
        FakeWeb.clean_registry
    end

end
