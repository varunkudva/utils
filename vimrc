""""""""""""""""""""""
" vkudvas' vimrc file
" 2016/04/02
""""""""""""""""""""""

"""""""""""""""""""""""""" Vundle configuration"""""""""""""""""""""""""
set nocompatible              " required
filetype off                  " required

" set the runtime path to include Vundle and initialize
set rtp+=~/.vim/bundle/Vundle.vim
call vundle#begin()

" alternatively, pass a path where Vundle should install plugins
"call vundle#begin('~/some/path/here')

" let Vundle manage Vundle, required
Plugin 'gmarik/Vundle.vim'

" Add all your plugins here (note older versions of Vundle used Bundle
" instead of Plugin)
"

"filesystem
Plugin 'scrooloose/nerdtree'
Plugin 'jistr/vim-nerdtree-tabs'
let NERDTreeIgnore=['\.pyc$', '\~$'] "ignore files in NERDTree
Plugin 'kien/ctrlp.vim'
Plugin 'jnurmine/Zenburn'
Plugin 'klen/python-mode'
Plugin 'majutsushi/tagbar'
Plugin 'morhetz/gruvbox'
Plugin 'altercation/vim-colors-solarized'
Plugin 'davidhalter/jedi-vim'
Plugin 'vim-airline/vim-airline'
Plugin 'vim-airline/vim-airline-themes'


" All of your Plugins must be added before the following line
call vundle#end()            " required
filetype plugin indent on    " required
"""""""""""""""""""""""""" Vundle configuration"""""""""""""""""""""""""

"automatic reloading of vimrc
autocmd! Bufwritepost .vimrc source %

set tags=~/tags

"Set clipboard copy paste
"set clipboard=unnamed

""" NERDTree settings
""" //NERDTree settings
let g:ctrlp_max_depth = 40
let g:ctrlp_max_files = 10000
"set background=dark
""""colorscheme
"let g:zenburn_old_Visual = 1
"let g:zenburn_force_dark_Background = 1
"let g:zenburn_alternate_Visual = 1
"let g:zenburn_high_Contrast = 1
"colorscheme zenburn
let g:solarized_contrast="high"
"let g:solarized_visibility="high"
colorscheme solarized
""""//colorscheme

"Set mouse and backspace
"set mouse=a
set bs=2
" allow backspacing over everything in insert mode
set backspace=indent,eol,start
set cursorline

"I dont like swapfiles
set noswapfile

" Rebind <Leader> key
let mapleader = ";"

nmap <C-O> :!git add %<CR><CR>
nmap <C-X> :files<CR>
nmap <leader>s :cs find s <C-R>=expand("<cword>")<CR><CR>      
nmap <leader>g :cs find g <C-R>=expand("<cword>")<CR><CR>      
nmap <leader>c :cs find c <C-R>=expand("<cword>")<CR><CR>      
"nmap <C-Q> :norm i//<CR>
nmap <C-n> :NERDTreeToggle<CR>
nmap <leader>t :TagbarToggle<CR>
nmap <leader>n :set invnumber<CR>
" nmap <C-E> :call ShowFuncName()<CR>

" easier moving of code blocks
" Try to go into visual mode (v), thenselect several lines of code here and
" then press ``>`` several times.
vnoremap < <gv  " better indentation
vnoremap > >gv  " better indentation

syntax on


set encoding=utf-8
set number
set tabstop=4
set shiftwidth=4
set expandtab
"set autochdir

"set 256 color mode in vim
set t_Co=256
"set t_AB=^[[48;5;%dm
"set t_AF=^[[38;5;%dm

set ruler
set showcmd

"
" if has("vms")
"   set nobackup          " do not keep a backup file, use versions instead
"   else
"     set backup            " keep a backup file
"     endif
"     set history=50          " keep 50 lines of command line history
"     set ruler               " show the cursor position all the time
"     set showcmd             " display incomplete commands
"     set incsearch           " do incremental searching
"
"     " For Win32 GUI: remove 't' flag from 'guioptions': no tearoff menu
"     entries
"     " let &guioptions = substitute(&guioptions, "t", "", "g")

" Don't use Ex mode, use Q for formatting
" map Q gq
"
" " This is an alternative that also works in block mode, but the deleted
" " text is lost and it only works for putting the current register.
" "vnoremap p "_dp
"
" Switch syntax highlighting on, when the terminal has colors
" Also switch on highlighting the last used search pattern.
"if &t_Co > 2 || has("gui_running")
"   syntax on
"    set hlsearch
"   endif

" Only do this part when compiled with support for autocommands.
if has("autocmd")

  " Enable file type detection.
  " Use the default filetype settings, so that mail gets 'tw' set to 72,
  " 'cindent' is on in C files, etc.
  " Also load indent files, to automatically do language-dependent indenting.
  filetype plugin indent on

  " Put these in an autocmd group, so that we can delete them easily.
  augroup vimrcEx
  au!

  " For all text files set 'textwidth' to 78 characters.
  autocmd FileType text setlocal textwidth=78

  " When editing a file, always jump to the last known cursor position.
  " Don't do it when the position is invalid or when inside an event handler
  " (happens when dropping a file on gvim).
  " Also don't do it when the mark is in the first line, that is the default
  " position when opening a file.
  autocmd BufReadPost *
    \ if line("'\"") > 1 && line("'\"") <= line("$") |
    \   exe "normal! g`\"" |
    \ endif

  augroup END

else

  set autoindent		" always set autoindenting on

endif " has("autocmd")

" Convenient command to see the difference between the current buffer and the
" file it was loaded from, thus the changes you made.
" Only define it when not defined already.
if !exists(":DiffOrig")
  command DiffOrig vert new | set bt=nofile | r # | 0d_ | diffthis
		  \ | wincmd p | diffthis
endif

"show matching braces
""set showmatch
set autoindent                " always set autoindenting on
set ts=4
set sw=4
set expandtab
set cinoptions=:0,(0
set nobackup
set wrap
:au BufWinEnter *.[ch] let w:m2=matchadd('ErrorMsg', '\%81v.', -1)
set autoread
set hlsearch
set incsearch
set ignorecase
