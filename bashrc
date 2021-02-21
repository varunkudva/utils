#General export Commands
export CSCOPE_EDITOR=vim
export PS1='\W>'
export CLICOLOR=yes
#export TERM='xterm-256color'
export GOPATH=$HOME/gocode:~/prizm/go

#export PATH=$PATH

#General aliases
alias vi=vim
alias ..="cd .."
alias sbrc="source ~/.bashrc"
alias ls="ls -G"
alias cdprog='cd ~/github/Programming/'
alias make=gmake #brew gnu make
alias preview='open -a preview'
alias lstree='tree -x -L'

export KUBECONFIG=/Users/vkudva/kubeconfig/config
cdniara() {
    . ~/.alias-niara
    cd $NIARA_SRC
}

# This is for setting tab titles in iterm
function title {
    echo -ne "\033]0;"$*"\007"
}

# setting up virtual env
# refer https://hackercodex.com/guide/python-development-environment-on-mac-osx/
venv2() {
    source ~/Virtualenvs/env2.7/bin/activate
}
venv() {
    source ~/Virtualenvs/venv3.x/bin/activate
}

# to update global pip packages in /user/local/bin
# refer https://hackercodex.com/guide/python-development-environment-on-mac-osx/
gpip(){
    PIP_REQUIRE_VIRTUALENV="0" pip "$@"
}

oak() {
    ssh root@10.43.7.215
}

c1() {
    ssh root@10.2.53.28
}

lite() {
   ssh ubuntu@obelix-ol-5461-0.test.pdt1.arubathena.com
}

n6() {
    ssh varun@niara6.niara.com
}

didev() {
    ssh ubuntu@52.34.172.115
}

didcpcap() {
    ssh ubuntu@10.43.15.164
}

direplay() {
    ssh root@10.43.15.159
}

dc2() {
    ssh ubuntu@10.43.15.152
}

dc1() {
    ssh ubuntu@10.43.15.151
}
chbranch() {
    for i in *; do cd $i; echo $i"---"; git co $1; cd ..;done
}

# aliases
source ~/.alias-git
source ~/.alias-prizm
source ~/.alias-niara

export PATH=/Users/vkudva/kafka_2.12-2.1.1/bin:$PATH
source ~/.iterm-title
