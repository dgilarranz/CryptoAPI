# frozen_string_literal: true

require 'rake/clean'
CLEAN.include 'cas'

namespace :test do
  require 'rspec/core/rake_task'

  RSpec::Core::RakeTask.new(:unit) do |t|
    t.pattern = FileList['spec/*/**/*_spec.rb'].reject { |file| file.include? 'app_spec.rb' }
  end

  RSpec::Core::RakeTask.new(:api) do |t|
    ENV['APP_ENV'] = 'test'
    ENV['API_KEY'] = 'TEST_API_KEY'
    t.pattern = 'spec/*/**/app_spec.rb'

    # Cleanup after tests
    at_exit { Rake::Task['clean'].execute }
  end

  RSpec::Core::RakeTask.new(:all) do
    Rake::Task['test:unit'].invoke
    Rake::Task['test:api'].invoke
  end
end
