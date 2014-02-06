module Sorcery
  module Providers
    # This class adds support for OAuth with mail.ru.
    #
    #   config.mailru.id = <id>
    #   config.mailru.key = <key>
    #   config.mailru.secret = <secret>
    #   ...
    #
    class Mailru < Base

      include Protocols::Oauth2

      attr_accessor :auth_path, :token_path, :client_id

      def initialize
        super

        @site       = 'https://connect.mail.ru/'
        @auth_path  = '/oauth/authorize'
        @token_path = '/oauth/token'
        @api_url    = 'http://appsmail.ru/platform/api'
      end

      def get_user_hash(access_token)
        user_hash = {}

        params = {
          method: 'users.getInfo',
          app_id: @client_id,
          session_id: access_token.token,
          secure: 0
        }

        params[:sig] = calculate_signature(params, access_token)

        response = access_token.get(@api_url, params: params)
        if user_hash[:user_info] = JSON.parse(response.body)
          user_hash[:user_info] = user_hash[:user_info][0]
          user_hash[:uid] = user_hash[:user_info]['uid']
        end
        user_hash
      end

      # calculates and returns the url to which the user should be redirected,
      # to get authenticated at the external provider's site.
      def login_url(params, session)
        self.authorize_url({ authorize_url: auth_path })
      end

      # tries to login the user from access token
      def process_callback(params, session)
        args = {}.tap do |a|
          a[:code] = params[:code] if params[:code]
        end

        get_access_token(args, token_url: @token_path, client_id: @client_id)
      end

      def calculate_signature(params, access_token)
        raw = params.map{|key, value| [key, value].join('=')}.sort.join
        raw = [access_token.params['x_mailru_vid'], raw, @secret].join
        Digest::MD5.hexdigest(raw)
      end

      def build_client(options = {})
        defaults = {
          site: @site,
          ssl: { ca_file: Sorcery::Controller::Config.ca_file },
          public_key: @key
        }
        ::OAuth2::Client.new(
          @client_id,
          @secret,
          defaults.merge!(options)
        )
      end
    end
  end
end
