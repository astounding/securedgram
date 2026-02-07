# frozen_string_literal: true
#
# SecureDGram::EnvLoader -- .env file parser
#
# Loads environment variables from a .env file.  Used by the daemon and
# all CLI tools to pick up configuration without requiring shell exports.

module SecureDGram
  module EnvLoader
    module_function

    ##
    ## Load a .env file into ENV.
    ##
    ## path  - Path to the .env file (default: .env in the current directory)
    ## force - If true, overwrite existing ENV values (used by HUP reload).
    ##         If false (default), only set values not already in ENV (||= semantics).
    ##
    ## Returns true if the file was loaded, false if not found.
    ##
    def load_dotenv(path = nil, force: false)
      path ||= File.join(Dir.pwd, '.env')
      return false unless File.file?(path)

      File.readlines(path).each do |line|
        line = line.strip
        next if line.empty? || line.start_with?('#')
        key, value = line.split('=', 2)
        next unless key && value
        value = value.strip
        ## Strip matching surrounding quotes (single or double):
        value = value[1..-2] if (value.start_with?('"') && value.end_with?('"')) ||
                                (value.start_with?("'") && value.end_with?("'"))
        key = key.strip
        if force
          ENV[key] = value
        else
          ENV[key] ||= value
        end
      end
      true
    end
  end
end
