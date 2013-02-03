require 'factory_girl'
require 'rotp'

FactoryGirl.define do
  factory :two_factor_authenticator, class: CASinoCore::Model::TwoFactorAuthenticator do
    user
    secret do |a|
      ROTP::Base32.random_base32
    end
    active true

    trait :inactive do
      active false
    end
  end
end
