# frozen_string_literal: true

require_relative "generator_test_case"

module AuthnzEleven
  class ApiTokensTest < GeneratorTestCase
    def test_default_identity_emits_independent_token_authentication
      run_generator %w[--email --password --api-tokens]

      assert_file "app/models/api_token.rb", /class ApiToken < ApplicationRecord/
      assert_file "app/controllers/concerns/api_token_authentication.rb", /module ApiTokenAuthentication/
      assert_file "app/controllers/settings/api_tokens_controller.rb", /class Settings::ApiTokensController/
      assert_file "app/views/settings/api_tokens/create.html.erb", /Copy this token now/
      assert_file "app/views/settings/api_tokens/index.html.erb", /API tokens/
      assert_file "config/routes.rb", /resources :api_tokens,\s+only: \[ :index, :create, :destroy \]/
      assert_file "app/models/user/authenticatable.rb", /has_many :api_tokens, dependent: :destroy/
      assert_file "test/models/api_token_test.rb"
      assert_file "test/controllers/settings/api_tokens_controller_test.rb"
      assert_file "app/controllers/concerns/authentication.rb" do |source|
        refute_includes source, "ApiTokenAuthentication"
      end
    end

    def test_namespaced_identity_keeps_its_own_tokens_and_routes
      run_generator %w[--email --password --namespaced --user-class=Realtor --api-tokens]

      assert_file "app/models/realtor/api_token.rb", /class Realtor::ApiToken < ApplicationRecord/
      assert_file "app/controllers/concerns/realtors/api_token_authentication.rb", /module Realtors::ApiTokenAuthentication/
      assert_file "app/controllers/realtors/settings/api_tokens_controller.rb", /Realtor::ApiToken.issue!/
      assert_file "config/routes.rb", /resources :api_tokens,\s+only: \[ :index, :create, :destroy \]/
    end

    def test_a_build_without_the_flag_omits_tokens
      run_generator %w[--email --password]

      assert_no_file "app/models/api_token.rb"
      assert_no_file "app/controllers/concerns/api_token_authentication.rb"
      assert_no_file "app/views/settings/api_tokens/index.html.erb"
    end
  end
end
