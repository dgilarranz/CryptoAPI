# frozen_string_literal: true
namespace :test do
  require 'rspec/core/rake_task'

  RSpec::Core::RakeTask.new(:unit) do |t|
    t.pattern = Dir['spec/*/**/*_spec.rb'].reject { |file| file.include? 'app.rb' }
  end

  RSpec::Core::RakeTask.new(:api) do |t|
    t.pattern = 'spec/*/**/app_spec.rb'
  end

  RSpec::Core::RakeTask.new(:all) do |t|
    t.pattern = 'spec/*/**/*_spec.rb'
  end
end
