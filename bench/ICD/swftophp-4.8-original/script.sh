tmux new-session -d -s swftophp -n "main" "afl-fuzz -i in -o out -M main -- ./swftophp @@"

# echo "Fuzzing session 'motivating-example' started!"
# echo "Use 'tmux attach -t motivating-example' to see progress."
