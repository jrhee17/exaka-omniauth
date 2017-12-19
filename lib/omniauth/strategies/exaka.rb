require 'omniauth-oauth2'
module OmniAuth
  module Strategies
    class Exaka < OmniAuth::Strategies::OAuth2
      include OmniAuth::Strategy
      option :client_options, {
          site: "http://exakadev.com:4000",
          authorize_url:
              "/oauth/authorize",
          token_url: "/oauth/token"
      }
      option :fields, [:name, :email]
      option :uid_field, :email
      def request_phase
        super
      end
      info do
        raw_info.merge("token" => access_token.token)
      end
      uid { raw_info["id"] }
      def raw_info
        @raw_info ||=
            access_token.get('/api/v1/me').parsed
      end
    end
  end
end
