require 'spec_helper'

require 'casino/authenticator'
require 'casino/external_authenticator'

describe CASino::Authenticator do
  subject {
    CASino::Authenticator.new
  }

  context '#validate' do
    it 'raises an error' do
      expect { subject.validate(nil, nil) }.to raise_error(NotImplementedError)
    end
  end
end

describe CASino::ExternalAuthenticator do
  subject {
    CASino::ExternalAuthenticator.new
  }

  context '#validate' do
    it 'raises an error' do
      expect { subject.validate(nil, nil) }.to raise_error(NotImplementedError)
    end
  end

  context '#view' do
    it 'raises an error' do
      expect { subject.view }.to raise_error(NotImplementedError)
    end
  end
end
