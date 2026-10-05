# frozen_string_literal: true

require "rails/generators/base"
require_relative "authnz_eleven_generator"
require_relative "../../authnz_eleven/wizard"

module AuthnzEleven
  # `bin/rails generate authnz_eleven:wizard`
  #
  # Picks the flags interactively, prints the command it assembled, and offers
  # to run it. The printed command is the point: it goes in a README, and
  # re-running it means the same thing.
  class WizardGenerator < Rails::Generators::Base
    desc "Pick authnz_eleven's flags interactively, then run the generator"

    # Not a gemspec dependency: huh isn't on RubyGems yet (the `huh` name there
    # belongs to an unrelated library, so don't send anyone to `gem install`),
    # and a gemspec can't declare a git source. It is also wanted exactly once.
    INSTALL = <<~MSG
      The wizard needs the `huh` gem for its terminal forms. Add it to your
      Gemfile, then `bundle install`:

        gem "huh", github: "marcoroth/huh-ruby", group: :development

      Or skip the wizard and write the flags yourself:

        bin/rails generate authnz_eleven --help
    MSG

    def pick_flags
      @flags = wizard.run
    rescue LoadError
      abort INSTALL
    end

    def report
      say ""
      say "  #{wizard.command}", :green
      say ""
    end

    def generate
      return say("Nothing generated.", :yellow) unless yes?("Run it now? [y/N]")

      AuthnzElevenGenerator.start(@flags)
    end

    private

    def wizard = @wizard ||= Wizard.new
  end
end
