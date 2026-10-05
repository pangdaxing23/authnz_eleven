# frozen_string_literal: true

require "active_support/core_ext/string/inflections"

module AuthnzEleven
  # Derives every name the generator needs from a single class name, using Rails'
  # inflector so the generated code agrees with what Rails itself computes at
  # runtime (route keys, table names, foreign keys).
  #
  # The default identity (class "User", not namespaced) is the plain case: User,
  # /sign_in, Session, Authentication. Only a renamed (`--user-class`) and/or
  # namespaced identity diverges, and every accessor below says how.
  class Identity
    DEFAULT_CLASS_NAME = "User"

    attr_reader :class_name

    def initialize(class_name: nil, namespaced: false)
      name = class_name.to_s.strip
      @class_name = (name.empty? ? DEFAULT_CLASS_NAME : name).camelize
      @namespaced = namespaced
    end

    def namespaced? = @namespaced

    # The canonical, unchanged build: plain "User", no namespace.
    def default? = @class_name == DEFAULT_CLASS_NAME && !namespaced?

    # Core inflections: "user"/"users" for the default, e.g. "realtor"/"realtors".
    def singular = @class_name.underscore
    def plural = singular.pluralize
    def table = plural
    def foreign_key = "#{singular}_id"

    # Route + controller slugs. They track the class name (for the default that is
    # the familiar user/users); the URL *path*, however, is only prefixed once
    # namespaced (see #path_prefix), so the default keeps top-level /sign_in.
    #
    # route_scope       -> route "as:" stem, e.g. user_sign_in_path
    # controller_module -> module: :users / Users::SessionsController
    def route_scope = singular
    def controller_module = plural

    # Camelized forms for class/module declarations in templates.
    # module_name     -> "Users"    (Users::SessionsController)
    # settings_module -> "Settings" (Settings::PasswordsController)
    def module_name = controller_module.camelize
    def settings_module = nested_module("Settings")

    # An area (settings, admin, teams) sits at the top level for the default
    # identity and inside the identity's own namespace once namespaced: its files,
    # its module, and its route helpers.
    def nested_path(name) = namespaced? ? "#{controller_module}/#{name}" : name
    def nested_module(name) = namespaced? ? "#{module_name}::#{name}" : name
    def nested_helper(name) = namespaced? ? "#{route_scope}_#{name}" : name

    # URL path scope: bare for the default identity (so /sign_in stays /sign_in),
    # the identity's own name once namespaced.
    def path_prefix = namespaced? ? singular : nil

    # Where the self-service area's controllers, views and tests are *filed*:
    # a plain top-level "settings" directory for the default identity. A namespaced
    # identity's settings controllers, by contrast, live *inside* the same outer
    # route scope as its other controllers (see namespaced_route_block), which sets
    # `module: identity.controller_module` once for everything nested in it — so
    # the directory must nest under controller_module here too, or the settings
    # controllers get filed (and named) under a namespace the routes never
    # actually point at.
    def settings_path_prefix = nested_path("settings")

    # The settings area's own base controller, mirroring AdminController: every
    # Settings:: controller inherits it, so an exemption that belongs to the
    # whole area is declared once.
    def settings_controller = "#{settings_module}Controller"
    def settings_controller_file = "#{settings_path_prefix}_controller"

    # The *route-helper* stem for that same area — not simply the directory with
    # slashes swapped. settings_path_prefix is plural (controller_module) so the
    # controllers file/name correctly under Admins::Settings::…, but the settings
    # routes nest inside the outer scope's `as: route_scope` (singular), so their
    # helpers are admin_settings_… — not admins_settings_…. Use this for
    # `#{…}_*_path/url`; use settings_path_prefix for file paths, and
    # settings_module for the module name.
    def settings_helper_prefix = nested_helper("settings")

    # A generic name (Session, Current, Team, ...) belongs to the default identity.
    # A namespaced identity nests its own copy inside its model class, where Rails
    # infers associations (Realtor's has_many :sessions finds Realtor::Session),
    # prefixes the table (realtor_sessions) and demodulizes foreign keys
    # (session_id), so no association needs a class_name.
    def namespaced_class(name) = namespaced? ? "#{@class_name}::#{name}" : name
    def table_for(klass) = klass.underscore.tr("/", "_").pluralize

    # Two identities can be signed in at once (separate cookies), never
    # clobbering each other.
    def session_class = namespaced_class("Session")
    def session_file = session_class.underscore
    def sessions_table = table_for(session_class)
    def cookie_name = namespaced? ? "#{singular}_session_token" : "session_token"

    # Each identity owns an independent set of authentication tunables, reachable
    # two ways (the initializer sets up both, pointing at the same object):
    #
    #   config_storage  -> Rails.configuration.x.user_auth  (the Rails-native slot,
    #                      source of truth; still works for anything expecting it)
    #   config_constant -> UserAuth                         (a short top-level alias
    #                      the generated code actually reads — UserAuth.session.…)
    #
    # config_reference is the constant: it's what every read site resolves to, so a
    # single seam flips them all. A namespaced identity gets its own pair (RealtorAuth /
    # Rails.configuration.x.realtor_auth) so two identities never share tunables.
    def config_namespace = "#{singular}_auth"
    def config_storage   = "Rails.configuration.x.#{config_namespace}"
    def config_constant  = "#{@class_name}Auth"
    def config_reference = config_constant
    def initializer_file = default? ? "authentication" : "#{singular}_authentication"

    # A namespaced identity's task gets its own namespace so it cannot sweep another identity's
    # sessions.
    def task_namespace = namespaced? ? singular : nil
    def rake_task(name) = ["authnz_eleven", task_namespace, name].compact.join(":")

    # The controller-level concerns. "Authentication" for the default identity
    # (included in ApplicationController); Realtors::Authentication once namespaced,
    # in the same namespace as the identity's controllers and included by its
    # base controller.
    def authentication_concern = nested_module("Authentication")
    def authentication_concern_file = authentication_concern.underscore
    def authorization_concern = nested_module("Authorization")
    def authorization_concern_file = authorization_concern.underscore

    # The base controller a namespaced identity's controllers inherit from
    # (e.g. Realtors::BaseController). Unused for the default identity, which wires
    # the concern straight into ApplicationController.
    def base_controller = "#{controller_module.camelize}::BaseController"
    def base_controller_file = "#{controller_module}/base_controller"

    # What this identity's own controllers (sessions, registrations, account
    # area, ...) inherit from: ApplicationController for the default identity;
    # the identity's own BaseController once namespaced, so its authentication
    # concern is never injected into the shared ApplicationController.
    def controller_superclass = namespaced? ? base_controller : "ApplicationController"

    # Mailers. Shared "UserMailer"/"InvitationMailer" for the default identity; a
    # namespaced identity gets its own so two identities' mailers (and mailer views,
    # which Rails locates by the mailer's underscored name) never collide.
    def mailer_class = namespaced? ? "#{@class_name}Mailer" : "UserMailer"
    def mailer_file = mailer_class.underscore

    def current_class = namespaced_class("Current")
    def current_file = current_class.underscore

    def event_class = namespaced_class("Event")
    def event_file = event_class.underscore
    def events_table = table_for(event_class)

    def api_token_class = namespaced_class("ApiToken")
    def api_token_file = api_token_class.underscore
    def api_tokens_table = table_for(api_token_class)

    def recovery_code_class = namespaced_class("RecoveryCode")
    def recovery_code_file = recovery_code_class.underscore
    def recovery_codes_table = table_for(recovery_code_class)

    # Named for the credential, not for one of its roles: this table holds passkeys
    # as well as second-factor security keys.
    def webauthn_credential_class = namespaced_class("WebauthnCredential")
    def webauthn_credential_file = webauthn_credential_class.underscore
    def webauthn_credentials_table = table_for(webauthn_credential_class)

    def password_history_class = namespaced_class("PasswordHistory")
    def password_history_file = password_history_class.underscore
    def password_histories_table = table_for(password_history_class)

    def invitation_class = namespaced_class("Invitation")
    def invitation_file = invitation_class.underscore
    def invitations_table = table_for(invitation_class)

    def omniauth_identity_class = namespaced_class("OmniauthIdentity")
    def omniauth_identity_file = omniauth_identity_class.underscore
    def omniauth_identities_table = table_for(omniauth_identity_class)

    def pending_registration_class = namespaced_class("PendingRegistration")
    def pending_registration_file = pending_registration_class.underscore
    def pending_registrations_table = table_for(pending_registration_class)

    def team_class = namespaced_class("Team")
    def team_file = team_class.underscore
    def teams_table = table_for(team_class)

    def membership_class = namespaced_class("Membership")
    def membership_file = membership_class.underscore
    def memberships_table = table_for(membership_class)

    # The two things an account and a sign-up-in-progress must agree about: what
    # identifies them, and what makes a password acceptable. Both are included by
    # the model and by PendingRegistration, so a form that validates while staged
    # still validates when it becomes a row.
    def principals_concern = namespaced_class("Principals")
    def principals_concern_file = principals_concern.underscore
    def password_policy_concern = namespaced_class("PasswordPolicy")
    def password_policy_concern_file = password_policy_concern.underscore

    def nav_partial = namespaced? ? "#{controller_module}/authnz_eleven_nav" : "shared/authnz_eleven_nav"

    def sudo_partial
      namespaced? ? "#{controller_module}/authnz_eleven_sudo_challenge" : "shared/authnz_eleven_sudo_challenge"
    end
  end
end
