# frozen_string_literal: true

require_relative "lib/authnz_eleven/version"

Gem::Specification.new do |spec|
  spec.name = "authnz_eleven"
  spec.version = AuthnzEleven::VERSION
  spec.authors = ["Patrick Ziller"]
  spec.email = ["zillerpatrick@gmail.com"]

  spec.summary = "A full-featured authentication system generator for Rails applications"
  spec.description = "Generates a pre-built, security-conscious authentication system into a Rails app: " \
                     "DB-backed sessions with idle/absolute timeouts, paranoid flows, magic links, TOTP MFA, " \
                     "an admin area, and more, all opt-in via flags. Inspired by authentication-zero."
  spec.homepage = "https://github.com/pangdaxing23/authnz_eleven"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.4.2"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "#{spec.homepage}/tree/master"
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/master/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore test/ .rubocop.yml .github/ AGENTS.md CONTRIBUTING.md Rakefile])
    end
  end
  spec.require_paths = ["lib"]

  spec.add_dependency "activerecord", "~> 8.0"
  spec.add_dependency "railties", "~> 8.0"
end
