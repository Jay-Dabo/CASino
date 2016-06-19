require 'casino/authenticator'

module CASino::AuthenticationProcessor
  extend ActiveSupport::Concern

  def validate_login_credentials(username, password)
    validate :authenticators do |authenticator_name, authenticator|
      authenticator.validate(username, password)
    end
  end

  def validate_external_credentials(params, cookies)
    validate :external_authenticators do |authenticator_name, authenticator|
      if authenticator_name == params[:external]
        authenticator.validate(params, cookies)
      end
    end
  end

  def validate(type, &validator)
    authentication_result = nil
    authenticators(type).each do |authenticator_name, authenticator|
      begin
        data = validator.call(authenticator_name, authenticator)
      rescue CASino::Authenticator::AuthenticatorError => e
        Rails.logger.error "Authenticator '#{authenticator_name}' (#{authenticator.class}) raised an error: #{e}"
      end

      if data
        authentication_result = { authenticator: authenticator_name, user_data: data }
        Rails.logger.info("Credentials for username '#{data[:username]}' successfully validated using authenticator '#{authenticator_name}' (#{authenticator.class})")
        break
      end
    end
    authentication_result
  end

  def load_user_data(authenticator_name, username)
    authenticator = authenticators(:authenticators)[authenticator_name]
    return nil if authenticator.nil?
    return nil unless authenticator.respond_to?(:load_user_data)
    authenticator.load_user_data(username)
  end

  def authenticators(type)
    authenticators ||= {}
    return authenticators[type] if authenticators.has_key?(type)
    authenticators[type] = begin
      CASino.config[type].each do |name, auth|
        next unless auth.is_a?(Hash)

        authenticator = if auth[:class]
                          auth[:class].constantize
                        else
                          load_authenticator(auth[:authenticator])
                        end

        CASino.config[type][name] = authenticator.new(auth[:options])
      end
    end
  end

  private
  def load_authenticator(name)
    gemname, classname = parse_name(name)

    begin
      require gemname unless CASino.const_defined?(classname)
      CASino.const_get(classname)
    rescue LoadError => error
      raise LoadError, load_error_message(name, gemname, error)
    rescue NameError => error
      raise NameError, name_error_message(name, error)
    end
  end

  def parse_name(name)
    [ "casino-#{name.underscore}_authenticator", "#{name.camelize}Authenticator" ]
  end

  def load_error_message(name, gemname, error)
    "Failed to load authenticator '#{name}'. Maybe you have to include " \
      "\"gem '#{gemname}'\" in your Gemfile?\n" \
      "  Error: #{error.message}\n"
  end

  def name_error_message(name, error)
    "Failed to load authenticator '#{name}'. The authenticator class must " \
      "be defined in the CASino namespace.\n" \
      "  Error: #{error.message}\n"
  end
end
