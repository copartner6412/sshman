package sshman

import "strings"

func CreateCommentForSubject(subject Subject) string {
	comments := []string{}
	users := subject.GetSSHUser()
	comments = append(comments, users...)

	hosts := []string{}
	comments = append(comments, hosts...)

	hostname := subject.GetHostname()

	if hostname != "" {
		hosts = []string{hostname}
	}

	hosts = append(hosts, subject.GetDomain()...)
	hosts = append(hosts, subject.GetIPv4()...)
	hosts = append(hosts, subject.GetIPv6()...)

	for _, user := range users {
		for _, host := range hosts {
			comments = append(comments, user+"@"+host)
		}
	}

	return strings.Join(comments, "")
}
