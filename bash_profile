#
# vkudva bash_profile
# Refer https://hackercodex.com/guide/mac-development-configuration/
#

# Set architecture flags
export ARCHFLAGS="-arch x86_64"

# Ensure user-installed binaries take precedence
export PATH=/usr/local/bin:$PATH

# Load .bashrc if it exists
test -f ~/.bashrc && source ~/.bashrc

# bash-completion
[ -f /usr/local/etc/bash_completion ] && . /usr/local/etc/bash_completion

#iterm window title
echo -ne "\033]0;"Title goes here"\007"
export PATH="/usr/local/opt/ruby/bin:$PATH"
