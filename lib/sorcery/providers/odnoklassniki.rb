module Sorcery
  module Providers
    # This class adds support for OAuth with odnoklassniki.ru.
    #
    #   config.odnoklassniki.key = <key>
    #   config.odnoklassniki.secret = <secret>
    #   ...
    #
    class Odnoklassniki < Base

      include Protocols::Oauth2

      attr_accessor :auth_path, :token_path, :client_id

      def initialize
        super

        @site           = 'http://www.odnoklassniki.ru/'
        @user_info_url  = 'http://api.odnoklassniki.ru/fb.do'
        @auth_path      = '/oauth/authorize'
        @token_path     = '/oauth/token.do'
      end

      def get_user_hash(access_token)
        user_hash = {}

        params = {
          method: 'users.getCurrentUser',
          application_key: @key
        }

        params[:sig] = calculate_signature(params, access_token.token)
        params[:access_token] = access_token.token

        response = access_token.get(@user_info_url, params: params)
        if user_hash[:user_info] = JSON.parse(response.body)
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

        get_access_token(args, method: 'users.getCurrentUser', token_url: 'http://api.odnoklassniki.ru/oauth/token.do', grant_type: 'authorization_code', client_id: @client_id, client_secret: @client_secret)
      end

      def calculate_signature(params, access_token)
        str = params.sort.collect { |c| "#{c[0]}=#{c[1]}" }.join('')
        secret_key = Digest::MD5.hexdigest("#{access_token}#{@secret}")
        Digest::MD5.hexdigest("#{str}#{secret_key}")
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
