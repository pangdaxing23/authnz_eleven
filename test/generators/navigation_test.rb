# frozen_string_literal: true

require_relative "generator_test_case"

module AuthnzEleven
  # The generated navigation chrome (shared/_authnz_eleven_nav) and its guarded
  # injection into the application layout. Boot coverage proves the partial
  # *renders* (every page in the generated suite carries it via the layout); these
  # fast tests pin what it contains, that a stock layout gets wired automatically,
  # and that a customized layout is left untouched.
  class NavigationTest < GeneratorTestCase
    LAYOUT = "app/views/layouts/application.html.erb"
    PARTIAL = "app/views/shared/_authnz_eleven_nav.html.erb"
    RENDER_LINE = %(<%= render "shared/authnz_eleven_nav" %>)

    def test_default_build_generates_the_partial_and_wires_the_stock_layout
      run_generator %w[--password --registration=open --admin-dashboard --email]

      assert_file PARTIAL do |nav|
        assert_match(/link_to "Settings", settings_path/, nav)
        assert_match(/button_to "Sign out", user_sign_out_path, method: :delete/, nav)
        assert_match(/link_to "Sign in", user_sign_in_path/, nav)
        assert_match(/link_to "Sign up", user_sign_up_path/, nav)
        assert_match(/link_to "Admin", admin_root_path/, nav)
      end

      # The stock dummy layout is wired automatically, right after <body>.
      assert_file LAYOUT, /<body>\s*#{Regexp.escape(RENDER_LINE)}\s*<%= yield %>/
    end

    def test_partial_omits_links_for_features_not_generated
      run_generator %w[--password --email --registration=closed]

      assert_file PARTIAL do |nav|
        refute_match(/Sign up/, nav)
        refute_match(/Admin/, nav) # no --admin-dashboard
        refute_match(/Stop impersonating/, nav) # no --impersonatable
      end
    end

    def test_a_customized_layout_is_left_untouched
      layout_path = File.join(destination_root, LAYOUT)
      customized  = %(<body class="app">\n    <header>My App</header>\n    <%= yield %>)
      seed_layout = File.read(layout_path).sub("<body>\n    <%= yield %>", customized)
      File.write(layout_path, seed_layout)

      run_generator %w[--password --registration=open --email]

      # Partial is still generated (it's always useful) ...
      assert_file PARTIAL
      # ... but the customized layout is never edited.
      assert_file LAYOUT do |layout|
        refute_match(/authnz_eleven_nav/, layout)
        assert_match(%r{<header>My App</header>}, layout)
      end
    end

    def test_nav_is_default_identity_only
      run_generator %w[--password --registration=open
                       --namespaced --user-class=Realtor --email]

      # A namespaced identity is a secondary portal; its helpers don't belong in the
      # app-wide layout, so no partial and no injection.
      assert_no_file PARTIAL
      assert_file LAYOUT do |layout|
        refute_match(/authnz_eleven_nav/, layout)
      end
    end
  end
end
