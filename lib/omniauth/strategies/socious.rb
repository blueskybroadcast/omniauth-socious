require 'omniauth-oauth2'
require 'builder'

module OmniAuth
  module Strategies
    class Socious < OmniAuth::Strategies::OAuth2
      option :name, 'socious'

      option :client_options, {
        domain: 'MUST BE PROVIDED',
        sso_token: 'MUST BE PROVIDED',
        sso_key: 'MUST BE PROVIDED',
        access_token: 'MUST BE PROVIDED'
      }

      uid { info[:uid] }

      info { raw_user_info }

      def request_phase
        redirect_url_param = CGI.escape(callback_url + "?ssotoken=#{sso_token}&slug=#{account_slug}")
        redirect login_page_url + '/redir=' + redirect_url_param
      end

      def callback_phase
        account = Account.find_by(slug: account_slug)
        @app_event = account.app_events.create(activity_type: 'sso')

        sso_token = request.params['ssotoken']

        if sso_token
          splitted_token_values = sso_token.split('-')
          @user_id = splitted_token_values.first
          @timestamp = splitted_token_values.second
          @hmac_val = splitted_token_values.last

          error = if !valid_token?
                    'Socious SSO failure: token hash invalid'
                  elsif timestamp_expired?
                    'Socious SSO failure: token expired'
                  else
                    nil
                  end

          if error
            Rails.logger.error error
            @app_event.logs.create(level: 'error', text: error)
            @app_event.fail!

            fail!(:invalid_credentials)
          end

          self.env['omniauth.auth'] = auth_hash
          self.env['omniauth.origin'] = '/' + request.params['slug']
          self.env['omniauth.redirect_url'] = request.params['redirect_url'].presence
          self.env['omniauth.app_event_id'] = @app_event.id

          finalize_app_event
          call_app!
        else
          error_message = "Socious SSO failure: 'ssotoken' parameter is absent!"
          Rails.logger.error error_message
          @app_event.logs.create(level: 'error', text: error_message)
          @app_event.fail!

          fail!(:invalid_credentials)
        end
      rescue Exception => e
        error_message = 'Socious SSO failure: unknown error.'
        Rails.logger.error error_message

        if @app_event
          @app_event.logs.create(level: 'error', text: error_message)
          @app_event.fail!
        end

        raise e
      end

      def get_user_info
        url = user_info_url + "/#{@user_id}"

        request_log = "Socious Get User Info Request:\nGET #{url}, Authorization: Bearer #{Provider::SECURITY_MASK}"
        Rails.logger.warn request_log
        @app_event.logs.create(level: 'info', text: request_log)

        response = RestClient.get(url, { :Authorization => "Bearer #{options.client_options.access_token}"})

        if response.code == 200
          response_log = "Socious Get User Info Response (code: #{response.code}):\n#{response.body}"
          Rails.logger.warn response_log
          @app_event.logs.create(level: 'info', text: response_log)

          parsed_response = JSON.parse response.body

          if parsed_response['inactive'].to_s != '1'
            error_message = 'Socious SSO: User is inactive'
            Rails.logger.error error_message
            @app_event.logs.create(level: 'error', text: error_message)

            fail!(:invalid_credentials)
          end

          {
            uid: parsed_response['user_id'].to_s,
            first_name: parsed_response['fname'],
            last_name: parsed_response['lname'],
            email: parsed_response['email'],
            username: parsed_response['user_id'],
            membership: parsed_response['membership']
          }
        else
          error_message = "Socious Get user info failure (code: #{response.code}):\n#{response.body}"
          Rails.logger.error error_message
          @app_event.logs.create(level: 'error', text: error_message)
          @app_event.fail!

          fail!(:unknown_error)
        end
      rescue RestClient::ExceptionWithResponse => e
        error_message =  "Socious Get user info failure (code: #{e.response.code}):\n#{e.response.body}"
        Rails.logger.error error_message
        @app_event.logs.create(level: 'error', text: error_message)
        @app_event.fail!

        fail!(:unknown_error)
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid)
        hash.info = info
        hash
      end

      def raw_user_info
        @raw_user_info ||= get_user_info
      end

      private

      def timestamp_expired?
        Time.at(@timestamp.to_i).utc < 5.minutes.ago.to_time.utc
      end

      def valid_token?
        digest = OpenSSL::Digest.new('sha256')
        data = "#{@user_id}#{@timestamp}"
        hexdigest = OpenSSL::HMAC.hexdigest(digest, sso_key, data)

        hexdigest == @hmac_val
      end

      def base_url
        options.client_options.domain.gsub(/\/$/, '')
      end

      def login_page_url
        base_url + '/l/li/in'
      end

      def user_info_url
        base_url + '/api/users'
      end

      def sso_token
        options.client_options.sso_token
      end

      def sso_key
        options.client_options.sso_key
      end

      def account_slug
        request.params['slug'] || session['omniauth.params']['origin'].gsub(/\//, '')
      end

      def finalize_app_event
        app_event_data = {
          user_info: {
            uid: uid,
            first_name: info[:first_name],
            last_name: info[:last_name],
            email: info[:email]
          }
        }

        @app_event.update(raw_data: app_event_data)
      end
    end
  end
end
