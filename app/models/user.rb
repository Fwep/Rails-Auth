class User < ApplicationRecord
  validates :username, uniqueness: true
  validates :username, :session_token, presence: true, uniqueness: true
  validates_presence_of :password_digest, message: "Password can't be blank"
  validates :password, length: {minimum: 6, allow_nil: true}

  attr_reader :password
  before_validation :ensure_session_token

  def self.find_by_credentials(username, password)
    user = User.find_by(username: username)
    if user.is_password?(password)
      return user
    else
      raise "You done goofed"
    end
  end

  def self.generate_session_token
    SecureRandom::urlsafe_base64
  end

  def reset_session_token!
    self.session_token = self.generate_session_token
    self.save!
  end

  def password=(pw)
    @password = pw
    self.password_digest = BCrypt::Password.create(password)
  end

  def is_password?(pw)
    BCrypt::Password.new(self.password_digest).is_password?(pw)
  end
  
  def ensure_session_token
    self.session_token ||= User.generate_session_token
  end
end
