# frozen_string_literal: true

require_relative "generator_test_case"

module AuthnzEleven
  # Emitted code that reads a config key by name is only correct if the emitted
  # initializer defines that key in the same build. Nothing else checks that pair:
  # the predicate truth tables cover which branch fires, and the boot suite runs
  # the flows a scenario happens to exercise, but a key missing only in some
  # unexercised corner would sail through both and raise NoMethodError on nil at
  # the moment a user asks for a link.
  #
  # Each rowless email link uses `generates_token_for` beside the record it names.
  # The generated token name and its config.tokens expiry key must stay aligned.
  class ConfigKeyCouplingTest < GeneratorTestCase
    # Every shape the model-owned email token definitions can take.
    PURPOSE_SHAPES = {
      "all three kinds" => %w[--password --registration=open --recoverable --magic-link --email],
      "verification only" => %w[--password --registration=open --email],
      "staged, phone-gated" => %w[--phone=required --omniauth --registration=open],
      "invitation only" => %w[--password --registration=invite-only --email],
      "magic link, no verification" => %w[--magic-link --no-verifiable --email],
      "reset, no verification" => %w[--password --recoverable --no-verifiable --email],
      "magic link and reset, no verification" =>
        %w[--password --magic-link --recoverable --no-verifiable --email]
    }.freeze

    PURPOSE_SHAPES.each do |name, flags|
      define_method("test_every_purpose_has_a_token_ttl_#{name.tr(" ,", "__")}") do
        run_generator flags

        missing = generated_token_names - token_config_keys
        assert_empty missing,
                     "#{flags.join(" ")} emits token definitions with no config.tokens key to " \
                     "read a TTL from: #{missing.join(", ")}"
      end
    end

    # The same agreement, one section of the initializer over. `config.rate_limits.*`
    # is checked in BOTH directions, because each has its own way of going wrong:
    #
    #   a key read with none defined  -> NoMethodError on nil at the moment somebody
    #                                    hits the endpoint
    #   a key defined with no reader  -> worse, because it is silent. It reads like a
    #                                    setting, and turning it down does nothing.
    #                                    `rate_limits.email_verification` sat that way
    #                                    until 2026-08-09.
    #
    # The tokens check above only needs the first direction, whereas the throttles
    # are spread across controllers where nothing lists them.
    RATE_LIMIT_SHAPES = {
      "default" => %w[--password --registration=open --email],
      "invite only" => %w[--password --registration=invite-only --email],
      "every mailer" => %w[--password --registration=open --recoverable --magic-link --email],
      "phone gated" => %w[--phone=required --password --registration=open],
      "sms code door" => %w[--sms-code --registration=open --email --phone],
      "no verification" => %w[--password --registration=open --no-verifiable --email]
    }.freeze

    RATE_LIMIT_SHAPES.each do |name, flags|
      define_method("test_rate_limit_keys_and_readers_agree_#{name.tr(" ", "_")}") do
        run_generator flags

        defined_keys = rate_limit_config_keys
        read_keys = rate_limit_reads

        assert_empty read_keys - defined_keys,
                     "#{flags.join(" ")} emits code reading config.rate_limits keys the " \
                     "initializer never defines: #{(read_keys - defined_keys).sort.join(", ")}"
        assert_empty defined_keys - read_keys,
                     "#{flags.join(" ")} defines config.rate_limits keys nothing reads, so " \
                     "tuning them does nothing: #{(defined_keys - read_keys).sort.join(", ")}"
      end
    end

    private

    def rate_limit_config_keys
      initializer = File.read(File.join(destination_root, "config/initializers/authentication.rb"))
      initializer.scan(/^\s*config\.rate_limits\.(\w+)\s*=/).flatten.uniq
    end

    def rate_limit_reads
      # Two shapes: the controllers splat the whole entry into `rate_limit`, while
      # Sudoable subscripts it for [:to]/[:within] by hand.
      Dir.glob(File.join(destination_root, "app/**/*.rb")).flat_map do |path|
        File.read(path).scan(/(?<!config\.)rate_limits\.(\w+)/).flatten
      end.uniq
    end

    def generated_token_names
      Dir.glob(File.join(destination_root, "app/models/**/*.rb")).flat_map do |path|
        File.read(path).scan(/generates_token_for :(\w+)/).flatten
      end.uniq
    end

    def token_config_keys
      initializer = File.read(File.join(destination_root, "config/initializers/authentication.rb"))
      initializer.scan(/^\s*config\.tokens\.(\w+)\s*=/).flatten
    end
  end
end
