require 'openssl'
require 'base64'
require "yaml"
require "tty-prompt"

CONFIG = File.expand_path(File.join("..", ".secrets.yml"), __FILE__)
KEYFILE = File.expand_path(File.join("..", ".keyfile"), __FILE__)

class Keyring
  attr_reader :secrets

  def initialize
    unless File.exist? KEYFILE
      passphrase = TTY::Prompt.new.mask "We need to generate a key file, please enter a passphrase: "
      File.open(KEYFILE, "w") do |f|
        f << OpenSSL::PKey::RSA.generate(8192).export(OpenSSL::Cipher.new('AES-128-CBC'), passphrase)
      end
    end
    @key = OpenSSL::PKey::RSA.new(File.read(KEYFILE))
    File.open(CONFIG, "w").close unless File.exist? CONFIG
    @secrets = YAML.load(File.read(CONFIG)) || {}
  end

  def get_password(service, user)
    content = @secrets.dig(service, user)
    @key.public_decrypt(Base64.decode64(content)) if content
  end

  def set_password(service, user, password)
    (@secrets[service] ||= {})[user] = Base64.encode64(@key.private_encrypt(password))
    File.open(CONFIG, "w") { |f| f << YAML.dump(@secrets) }
  end
end

if __FILE__ == $0
  k = Keyring.new
  if ARGV[0]
    if ARGV[1]
      puts k.get_password(*ARGV)
    else
      puts k.secrets[ARGV[0]].keys
    end
  else
    puts k.secrets.keys
  end
end
