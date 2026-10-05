Rails.application.routes.draw do
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check

  # Render dynamic PWA files from app/views/pwa/* (remember to link manifest in application.html.erb)
  # get "manifest" => "rails/pwa#manifest", as: :pwa_manifest
  # get "service-worker" => "rails/pwa#service_worker", as: :pwa_service_worker

  # Defines the root path route ("/"). authnz_eleven's generated redirects call
  # root_path/root_url for the default (unscoped) identity but deliberately don't
  # choose a destination — a real host app supplies one, so the fixture does too.
  # It has to be one of this app's own controllers: see HomeController for why a
  # Rails-internal one (rails/health#show) made root_path untestable.
  root "home#index"
end
