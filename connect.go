package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"log"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

func connectModule() {
	instances := listInstances()
	var instanceid int
	scanned, err := fmt.Scan(&instanceid)
	if scanned != 1 || err != nil || instanceid < 0 || instanceid > len(instances.Reservations) {
		log.Fatal("incorrect instance selection. Please enter id (0...n) of instance")
	}
	connectInstanceId := instances.Reservations[instanceid].Instances[0].InstanceId

	connectToInstance(*connectInstanceId)

}

func connectToInstance(instanceId string) {
	time.Sleep(time.Duration(time.Second * 5))
	port := "22"
	instance, err := client.DescribeInstances(context.TODO(), &ec2.DescribeInstancesInput{
		InstanceIds: []string{instanceId},
	})

	if err != nil {
		log.Fatalln(err)
	}

	ip := *instance.Reservations[0].Instances[0].PublicIpAddress

	instanceOs := "linux"

	//	fmt.Println("tags = ", *&instance.Reservations[0].Instances[0].Tags)
	for _, t := range *&instance.Reservations[0].Instances[0].Tags {
		fmt.Printf("t.key = %s, t.val = %s\n\n", *t.Key, *t.Value)
		if *t.Key == "distribution" {
			if *t.Value == "windows" {
				fmt.Println("\n\n!!! setting intsance os to windows ")
				instanceOs = "windows"
				port = "3389"
			}
		}
	}

	var winpass string
	fmt.Println("!!!instance os!!!", instanceOs)
	if instanceOs == "windows" {
		winpass = encryptPass(getWindowsPassword(instanceId))
		fmt.Println("winpass = ", winpass)

		fmt.Println("remmina", "-c", "rdp://administrator:'"+winpass+"'@"+ip)

		cmd := exec.Command("remmina", "-c", "rdp://administrator:"+winpass+"@"+ip+"")

		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		fmt.Println("Attemtping to connect with remmina")
		cmd.Run()
	}
	fmt.Println("IP Address = ", ip)

	if instanceOs == "linux" {
		waitForSocket(ip, port)
		cmd := exec.Command("ssh", "-o", "StrictHostKeyChecking=no", "-l", "admin", ip)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		err = cmd.Run() // add error checking

		if err != nil {
			log.Fatalln("!! ssh exited with non zero status !!")
		}
	}
}

func waitForSocket(host string, port string) {

	for i := 0; i < 120; i++ {
		tcpServer, err := net.ResolveTCPAddr("tcp", host+":"+port)

		if err != nil {
			fmt.Println(err)
		}

		conn, err := net.DialTCP("tcp", nil, tcpServer)
		if err != nil {
			fmt.Println("dial error ", err)
			fmt.Println(host, port)
			time.Sleep(time.Duration(time.Second * 1))
			continue
		}
		conn.Close()
		break
	}
}
func encryptPass(pass string) string {
	cmd := exec.Command("remmina", "--encrypt-password")
	var out bytes.Buffer
	var in bytes.Buffer = *bytes.NewBuffer([]byte(pass))
	var error bytes.Buffer

	cmd.Stdin = &in
	cmd.Stdout = &out
	cmd.Stderr = &error
	cmd.Run()

	regex := "(?m)^Encrypted password: (.*$)"
	re := regexp.MustCompile(regex)
	match := re.Find([]byte(out.String()))
	return strings.Replace(string(match), "Encrypted password: ", "", 10)
}

func getWindowsPassword(instanceId string) string {
	fmt.Println("getting windows password")

	var passwordData *ec2.GetPasswordDataOutput
	var err error
	var attempts = 26
	var password string
	sleeptime := 10

	for attempts > 0 {
		passwordData, err = client.GetPasswordData(context.TODO(), &ec2.GetPasswordDataInput{
			InstanceId: aws.String(instanceId),
		})
		if err != nil {
			log.Fatal("coult not retrieve password data", err)
		}

		if *passwordData.PasswordData != "" {
			password = *passwordData.PasswordData
			break
		}
		time.Sleep(time.Duration(sleeptime) * time.Second)
		attempts--
		fmt.Println("This can take some time sleeping for ", sleeptime, " seconds")
	}

	cmd := exec.Command("openssl", "pkeyutl", "-decrypt", "-inkey", getHome()+"/.ssh/ec2go")
	var out bytes.Buffer
	var in bytes.Buffer
	var error bytes.Buffer
	in = *bytes.NewBuffer([]byte(password))
	passdata, err := base64.StdEncoding.DecodeString(password)
	in = *bytes.NewBuffer(passdata)

	cmd.Stdout = &out
	cmd.Stdin = &in
	cmd.Stderr = &error
	err = cmd.Run()
	if err != nil {
		fmt.Println("error is", error.String())
		log.Fatal(err)
	}

	return out.String()
}
