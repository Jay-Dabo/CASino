require 'casino/external_authenticator'

# The external static authenticator is just a simple example.
# Never use this authenticator in a production environment!
class CASino::StaticExternalAuthenticator < CASino::Authenticator

  # @param [Hash] options
  def initialize(options)
    @users = options[:users] || {}
  end

  def validate(params, cookies)
    token = :"#{cookies[:token]}"
    if @users.include?(token)
      {
        username: @users[token][:username],
        extra_attributes: @users[token].except(:token)
      }
    else
      false
    end
  end

  def view
    return nil
  end

end
