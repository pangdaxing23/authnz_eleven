# frozen_string_literal: true

require "test_helper"

class AuthnzElevenTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::AuthnzEleven::VERSION
  end

  def test_gem_does_not_define_generated_controller_concern_namespace
    refute Object.const_defined?(:Authentication)
  end
end
