# netlify-lane2

Scratch repo for authorized security testing against Netlify's HackerOne program
(build-container network position). Contains no application code.

The build command runs a read-only recon script that measures the four things
Netlify's program policy explicitly keeps in scope for site builds: privilege
escalation to root, secrets not already accessible to the build user, container
escape, and reachability of the orchestration control plane.
