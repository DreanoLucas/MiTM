if [ $1 = "clone" ]
	then
	git clone "https://github.com/DreanoLucas/SAE24.git"
fi
if [ $1 = "push" ]
	then 
	git add ~/SAE24/ 
	git commit
	git config --global push.default simple
	echo -n "Quelle branche ?"
	read $branch
	echo ouais
	git push origin $branch
fi
