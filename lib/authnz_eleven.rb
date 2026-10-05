# frozen_string_literal: true

require_relative "authnz_eleven/version"
require_relative "authnz_eleven/principal"
require_relative "authnz_eleven/principals"

module AuthnzEleven
  class Error < StandardError; end

  # authnz_eleven ships no runtime code: it is simply a Rails generator. The
  # generator is discovered automatically from lib/generators when the gem
  # is in your Gemfile. See:
  #
  #   bin/rails generate authnz_eleven --help
end
