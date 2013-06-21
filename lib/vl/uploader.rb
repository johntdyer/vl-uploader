require "vl/uploader/version"
require 'chef/knife'
require 'digest/md5'
require 'fileutils'
require 'mime/types'
require 'pathname'
require 's3'
require 'tmpdir'
require 'voxconfig'
require 'yaml'


module Vl

  class Uploader
    $: << File.expand_path(File.dirname(__FILE__))

    attr_reader :tmp_path

    def initialize(opts={})
      @config = VoxConfig.new(Dir.pwd)
      @tmp_path = opts[:path]

    end


    def delete_tmp_dir
      FileUtils.remove_entry_secure(@tmp_path)
    end
  end



  def get_folder_name
    if @config.project_name
      return @config.project_name
    else
      get_cookbook_name
    end
  end

  def get_cookbook_name
    name = IO.read(Berkshelf.find_metadata).match(/^name.*/).to_s.split('"')[1]
    if name.nil?
      return Dir.pwd.split("/")[-1]
    else
      return name
    end

  end

  def upload_cookbooks(file)
    service = S3::Service.new({
                                :access_key_id     =>  @config.aws_key,
                                :secret_access_key =>  @config.aws_secret
    })
    bucket = service.buckets.find(@config.bucket_name)
    puts ui.highline.color  "== Uploading cookbook [#{file}]", :green

    ## Only upload files, we're not interested in directories
    if File.file?(file)
      remote_file = "#{get_folder_name}/#{file.split("/")[-1]}"

      begin
        obj = bucket.objects.find_first(remote_file)
        if yes? "This cookbook version already exists, do you want to overwrite it ?", :red
          puts ui.highline.color  "== Ok, we'll overwrite it", :green
        else
          puts ui.highline.color  "== Ok, exiting", :green
          exit 0
        end
      rescue
        obj = nil
      end

      puts ui.highline.color  "== Uploading http://#{@config.bucket_name}/#{get_folder_name}/#{file.split("/")[-1]}", :blue
      obj = bucket.objects.build(remote_file)
      obj.content = open(file)
      obj.content_type = MIME::Types.type_for(file).to_s
      obj.save

    end
    puts ui.highline.color  "== Done syncing #{file.split('/')[-1]}",:green
  end

end
end

end
end
