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
      def build_access_token 
        verifier = request.params['code'] 
        redirect_uri = URI.parse(callback_url).tap { |uri| uri.query = Rack::Utils.parse_query(uri.query).reject { |k,v| %w(code state).include?(k) }.to_query }.to_s 
        client.auth_code.get_token(verifier, {redirect_uri: redirect_uri}.merge(token_params.to_hash(symbolize_keys: true)), deep_symbolize(options.auth_token_params)) 
      end
      uid { raw_info["id"] }
      def raw_info
        @raw_info ||=
            access_token.get('/api/v1/me').parsed
      end
    end
  end
end
