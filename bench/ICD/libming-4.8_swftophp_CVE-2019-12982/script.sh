tmux new-session -d -s swftophp -n "main" "afl-fuzz -i in -o out -M main -- ./swftophp @@"
