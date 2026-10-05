# The dummy app's root. authnz_eleven never generates a root route — a real host
# app supplies one — but root_path has to resolve, because the generated
# redirects call it.
#
# It points at a controller of *this* app on purpose. The previous target,
# rails/health#show, is a Rails-internal controller that doesn't inherit from
# ApplicationController, so requests to it skip resume_session and every other
# authentication callback. A test that hit root_path expecting the pipeline to
# have run would silently measure nothing.
#
# Public, like most real homepages — and written with `raise: false` because this
# fixture also has to load *before* the generator has run (CI eager-loads the
# ungenerated dummy), when there is no require_authentication callback to skip.
class HomeController < ApplicationController
  skip_before_action :require_authentication, raise: false

  def index
  end
end
