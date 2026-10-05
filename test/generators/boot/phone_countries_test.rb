# frozen_string_literal: true

require_relative "boot_test_case"

module AuthnzEleven
  class PhoneCountriesBootTest < BootTestCase
    def test_all_countries_by_default_and_an_optional_allowlist
      generate!(*%w[--phone --email --password --registration=open-and-invites])
      bundle_install!
      prepare_database!

      probe = <<~RUBY
        numbers = { "US" => "+14158264001", "CA" => "+14169671111", "GB" => "+442071838750" }
        fields = [[User, :phone], [PendingRegistration, :phone], [User, :pending_phone], [Invitation, :sent_to]]
        fields.each do |model, attribute|
          validator = model.validators_on(attribute).find { |item| item.is_a?(PhoneValidator) }
          numbers.each do |country, number|
            record = model.new(attribute => number)
            validator.validate_each(record, attribute, record.public_send(attribute))
            allowed = UserAuth.phone.allowed_countries
            expected = allowed.nil? || allowed.include?(country)
            abort "Unexpected country validation: \#{model}.\#{attribute} \#{country}" unless record.errors[attribute].empty? == expected
          end
          record = model.new(attribute => "6494461709")
          validator.validate_each(record, attribute, record.public_send(attribute))
          abort "Malformed local number accepted: \#{model}.\#{attribute}" if record.errors[attribute].empty?
        end
      RUBY

      run_in_app!("bin/rails", "runner", probe)

      initializer = File.join(app_dir, "config/initializers/authentication.rb")
      contents = File.read(initializer).sub(
        "config.phone.allowed_countries = nil",
        "config.phone.allowed_countries = %w[US CA]"
      )
      File.write(initializer, contents)
      run_in_app!("bin/rails", "runner", probe)
    end
  end
end
