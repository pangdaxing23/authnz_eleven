# frozen_string_literal: true

require_relative "generator_test_case"

module AuthnzEleven
  # A second identity must never depend on what the first one wrote. Each identity
  # is rendered alone; any file two of them both write has to come out
  # byte-identical, or the later run keeps whichever copy got there first and the
  # app works or breaks depending on the order the generator was run in.
  class IdentityIsolationTest < GeneratorTestCase
    BUILDS = {
      "plain" => %w[--password --email],
      "teams_session" => %w[--password --teams=session --registration=open-and-invites --admin-dashboard
                            --impersonatable --sudoable --second-factor=totp,webauthn --captchable --email],
      "teams_scope" => %w[--password --teams --admin-dashboard --trackable --omniauth --email],
      "passkeys" => %w[--passkey --magic-link --captchable --trackable --email],
      "texting" => %w[--phone --sms-code --second-factor=webauthn --captchable --username],
      "phone_verified" => %w[--password --phone --second-factor --omniauth --email]
    }.freeze

    def test_files_two_identities_both_write_render_identically
      defaults = BUILDS.transform_values { |flags| render(flags) }
      namespaced = BUILDS.transform_values { |flags| render(flags + %w[--namespaced --user-class=Merchant]) }

      mismatches = defaults.flat_map do |first, first_files|
        namespaced.flat_map do |second, second_files|
          (first_files.keys & second_files.keys)
            .reject { |path| first_files[path] == second_files[path] }
            .map { |path| "#{path} (#{first} then #{second})" }
        end
      end

      assert_empty mismatches.uniq, "files both identities write but render differently:\n#{mismatches.uniq.join("\n")}"
    end

    private

    def render(flags)
      Dir.mktmpdir do |dir|
        seed_destination_from_dummy_app(dir)
        skeleton = files_in(dir)
        run_generator(flags, destination_root: dir)
        files_in(dir).reject { |path, _| skeleton.key?(path) || path.start_with?("db/migrate/") }
      end
    end

    def files_in(dir)
      Dir.glob("#{dir}/**/*").select { |path| File.file?(path) }.to_h do |path|
        [path.delete_prefix("#{dir}/"), File.read(path)]
      end
    end
  end
end
