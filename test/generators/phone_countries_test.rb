# frozen_string_literal: true

require_relative "generator_test_case"

module AuthnzEleven
  class PhoneCountriesTest < GeneratorTestCase
    def test_phone_country_config_is_shared_by_all_phone_validations
      run_generator %w[--phone --email --password --registration=open-and-invites]

      assert_file "config/initializers/authentication.rb", /config\.phone\.allowed_countries = nil/
      assert_file "config/initializers/authentication.rb", /# config\.phone\.allowed_countries = %w\[US CA\]/
      %w[app/models/concerns/principals.rb app/models/user/phone_verifiable.rb app/models/invitation.rb].each do |path|
        assert_file path, /countries: UserAuth\.phone\.allowed_countries/
        assert_file path, /format: :e164/
      end
      assert_file "app/models/pending_registration.rb", /include Principals/
    end

    def test_phone_only_invitations_use_the_identity_config
      run_generator %w[--phone --sms-code --registration=open-and-invites --user-class=Merchant --namespaced]

      assert_file "app/models/merchant/invitation.rb", /countries: MerchantAuth\.phone\.allowed_countries/
    end
  end
end
