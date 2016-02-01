require 'oauth/request_proxy/rack_request'
require 'securerandom'

module LtiProvider
  class LtiController < LtiProvider::ApplicationController
    skip_before_filter :require_lti_launch
    after_filter :allow_iframe, only: [:launch, :cookie_test, :consume_launch]

    def launch
      params['oauth_consumer_key'].strip!
      lti_credential = lti_credentials_object(params['oauth_consumer_key']) if params['oauth_consumer_key'].present?
      provider = lti_provider_by_credentials(lti_credential, params)
      launch = Launch.initialize_from_request(provider, request)

      if !launch.valid_provider?
        msg = launch.lti_errormsg
        return show_error msg
      elsif launch.save
        session[:cookie_test] = true
        redirect_to cookie_test_path(nonce: launch.nonce)
      else
        return show_error "Unable to launch #{LtiProvider::XmlConfig.tool_title}. Please check your External Tools configuration and try again."
      end
    end

    def cookie_test
      consume_launch
      return
      if session[:cookie_test]
        # success!!! we've got a session!
        consume_launch
      else
        render
      end
    end

    def consume_launch
      launch = Launch.where("created_at > ?", 5.minutes.ago).find_by_nonce(params[:nonce])

      if launch
        set_data_to_session(launch)
        res = gen_link(launch, params)
        link = res[0]
        new_user = res[1]
        if new_user
          capture_launch_event(launch, new_user)
          redirect_to link
        else
          return show_error "Only non-anonymous users can launch this assignment. Please change the privacy to public and try again."
        end
      else
        return show_error "The tool was not launched successfully. Please try again."
      end
    end

    # def configure
    #   respond_to do |format|
    #     format.xml do
    #       render xml: Launch.xml_config(lti_launch_url)
    #     end
    #   end
    # end

    protected
      def show_error(message)
        render text: message
      end

    private
      def allow_iframe
        response.headers.except! 'X-Frame-Options'
      end

      def new_user_params(email, username, partner_name, launch)
        provider_params = launch[:provider_params]
        user_params = {provider: partner_name, promo: partner_name}
        user_params[:username] = username if username.present?
        user_params[:password_confirmation] = user_params[:password] = SecureRandom.hex
        user_params[:email] = email if email.present?
        if provider_params['lis_person_name_given'].present?
          user_params[:first_name] = provider_params['lis_person_name_given'].strip
        end
        if provider_params['lis_person_name_family'].present?
          user_params[:last_name] = provider_params['lis_person_name_family'].strip
        end
        user_params[:state] = User::STATE_CONFIRMED
        if provider_params['user_id'].present?
          user_params[:provider_user_id] = provider_params['user_id']
        end
        if provider_params['roles'].downcase.include? 'instructor'
          user_params[:role] = User::TEACHER_ROLE
        end
        user_params[:role] ||= User::STUDENT_ROLE
        if user_params[:role] == User::STUDENT_ROLE
          lti_credentials = lti_credentials_object(launch['oauth_consumer_key'])
          if lti_credentials.is_a? LtiCredential
            user_params[:managed] = true if user_params[:email].blank?
            user_params[:account_owner_ids] = [lti_credentials.user_id]
          end
        end
        user_params
      end

      def lti_credentials_object(key)
        unless @lti_credentials
          @lti_credentials = LtiCredential.where(lti_key: key).first
          @lti_credentials ||= Doorkeeper::Application.where(uid: key).first
        end
        @lti_credentials
      end

      def get_partner_name(launch)
        unless @partner_name
          lti_credentials = lti_credentials_object(launch['oauth_consumer_key'])
          if lti_credentials.present? and lti_credentials.is_a? Doorkeeper::Application
            @partner_name = app.name
          else
            uri = launch[:provider_params]['launch_presentation_return_url']
            @partner_name = URI.parse(uri).host.sub(/^www\./, '')
          end
        end
        @partner_name
      end

      def get_teacher_id(launch)
        lti_credentials = lti_credentials_object(launch['oauth_consumer_key'])
        if lti_credentials.present? and lti_credentials.is_a? LtiCredential
          return lti_credentials.user_id
        end
        nil
      end

      def lti_provider_by_credentials(lti_credentials, params)
        return if lti_credentials.blank?
        if lti_credentials.is_a? Doorkeeper::Application
          return IMS::LTI::ToolProvider.new(lti_credentials.uid, lti_credentials.secret, params)
        end
        if lti_credentials.is_a? LtiCredential
          return IMS::LTI::ToolProvider.new(lti_credentials.lti_key, lti_credentials.lti_secret, params)
        end
      end

      def set_data_to_session(launch)
        [:account_id, :course_name, :course_id, :canvas_url, :tool_consumer_instance_guid,
         :user_id, :user_name, :user_roles, :user_avatar_url].each do |attribute|
          session["lti_#{attribute}".to_sym] = launch.public_send(attribute)
        end
      end

      def get_resource_id(launch)
        launch[:provider_params]['custom_opened_resource_id']
      end

      def gen_link(launch, params)
        resource_id = get_resource_id(launch)
        launch_presentation_return_url = launch[:provider_params]['launch_presentation_return_url']

        link = "#{ENV['LTI_RUNNER_LINK'].sub(':resource_id', resource_id.to_s)}"
        if launch[:provider_params]['custom_oauth_access_token'].present?
          access_token = launch[:provider_params]['custom_oauth_access_token']
          token = Doorkeeper::AccessToken.by_token access_token if access_token
        end
        if token and token.accessible? and token.respond_to?('resource_owner') and
            token.application.uid == launch[:provider_params]['oauth_consumer_key']
          link += "oauth_access_token=#{launch[:provider_params]['custom_oauth_access_token']}&"
          new_user = token.resource_owner
        else
          new_user = get_user_by_lms_data(launch)
          # get/create user, authorize user and send auth data
          link += "authToken=#{new_user.api_key.access_token}&userId=#{new_user.id}&" if new_user
        end
        link += "lti_nonce=#{params[:nonce]}&launch_presentation_return_url=#{CGI.escape(launch_presentation_return_url)}"
        [link, new_user]
      end

      def get_user_by_lms_data(launch)
        email = launch[:provider_params]['lis_person_contact_email_primary']
        if email.present?
          if email.include? '@'
            user = User.where(email: email.downcase).first
          else
            username = email
          end
        end
        unless user
          username = get_username(username, launch)
          partner_name = get_partner_name(launch)
          user = User.where(provider: partner_name, username: username).first if username
          unless user
            # create user
            user_params = new_user_params(email, username, partner_name, launch)
            model = User.user_model(user_params[:role])
            user = model.create(user_params)
            user.email = nil unless user.valid? # sometimes we have wrong email
            unless user.save
              return nil
            end
          end
        end
        user
      end

      def get_username(username, launch)
        #for moodle
        if launch[:provider_params]['ext_user_username'].present?
          username ||= launch[:provider_params]['ext_user_username'].strip.downcase
        end
        #for schoology
        if launch[:provider_params]['custom_username'].present?
          username ||= launch[:provider_params]['custom_username'].strip.downcase
        end
        #for canvas
        if launch[:provider_params]['custom_canvas_user_login_id'].present?
          username ||= launch[:provider_params]['custom_canvas_user_login_id'].strip.downcase
        end
        username
      end

      def get_user_id(user_id, launch)
        #for canvas
        if launch[:provider_params]['custom_canvas_user_id'].present?
          user_id ||= launch[:provider_params]['custom_canvas_user_id'].strip.downcase
        end
        user_id
      end

      def capture_launch_event(launch, user)
        LtiLaunchEvent.capture_event(
            user_id: user.id,
            resource_id: get_resource_id(launch),
            ref_id: get_teacher_id(launch),
            partner_name: get_partner_name(launch),
            lms_name: launch[:provider_params]['tool_consumer_info_product_family_code'],
            lms_version: launch[:provider_params]['tool_consumer_info_version']
        )
      end

  end
end
