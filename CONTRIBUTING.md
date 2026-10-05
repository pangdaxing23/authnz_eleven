# Contributing

## Setup

```sh
git clone https://github.com/pangdaxing23/authnz_eleven.git
cd authnz_eleven
bundle install
(cd test/dummy && bundle install)
```

You need Ruby 3.4.2 or newer. Docker is only needed to test against PostgreSQL and MySQL.

## Layout

- `lib/generators/authnz_eleven/authnz_eleven_generator.rb` is the generator. It defines the flags and the helper methods the templates call. This file is a beast.
- `lib/generators/authnz_eleven/templates/` holds all templates, including the tests the app ships with.
- `lib/authnz_eleven/` holds the POROs the generator uses, such as `Identity`, `Principal` and `Wizard`.
- `test/dummy/` is a bare Rails app. The tests generate into copies of it.
- `test/generators/scenarios.rb` lists named flag combinations. Both the completeness check and the boot suite read it.

## Tests

```sh
rake                        # unit tests, fast generator tests, rubocop
rake test:boot              # every scenario, built and tested on SQLite
rake test:boot:postgresql   # the same on PostgreSQL, in a throwaway Docker container
rake test:boot:mysql        # the same on MySQL, in a throwaway Docker container
```

`rake` takes seconds. Run it often.

The boot suite is slow. For each scenario it copies `test/dummy`, runs the generator, bundles, lints with omakase, checks that the app boots, and runs the app's own generated test suite. The PostgreSQL and MySQL runs take about seven minutes each.

To run one scenario, pass a filter after `--`:

```sh
bundle exec ruby -Itest -e 'require_relative "test/generators/boot/boot_scenarios_test"' -- -n test_boot_kitchen_sink
```

To test against an older Rails, see `test/dummy/Appraisals`.

## Adding a flag or a template

- Every template must be built by at least one scenario. `scenario_completeness_test.rb` fails otherwise. Add the flag to an existing scenario where it fits, or add a new one.
- Every generated controller needs a generated test that exercises it. `behavioral_coverage_test.rb` lists each controller as covered, a known gap, or skipped with a reason.
- Generated tests must pass inside every generated app that includes them. Run the boot suite before you open a pull request.

## Style

- Prefer removing code to adding it. Every conditional makes the generator harder to follow, so look for a way to combine or reframe before you add one.
- Comment sparingly. If code needs a comment to make sense, try to make the code clearer first.
- Generated code gets no comments, unless I say so, and it should pass `rubocop-rails-omakase` with no offenses.
- Keep user-facing text plain and short.

## Changelog

Add user-visible changes to `CHANGELOG.md`.
