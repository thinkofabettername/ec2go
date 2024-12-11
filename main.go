package main

// test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/aws/smithy-go"
)

// globals
var client *ec2.Client
var tagKey string = "ec2go"
var cargs cliArgs
var starttime = time.Now().Unix()

var Version = "No version supplied at build time"
var BuildDate = "No build date supplied at build time"

var validModules []string = []string{
	"run",
	"terminate",
	"list",
	"connect",
	"rdisk",
}

type ec2goListInstancesInterface struct {
	silent bool
}

type cliArgs struct {
	modules       []string
	rampages      []string
	instanceTypes []string
	regions       []string
	helps         []string
	distros       []string
	sshs          []string
}

func main() {

	fmt.Println("Version: ", Version)
	fmt.Println("BuildDate: ", BuildDate)

	cargs = handleArgs()

	if len(cargs.regions) == 1 {
		cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(cargs.regions[0]))
		if err != nil {
			log.Fatal(err)
		}
		client = ec2.NewFromConfig(cfg)

	} else {
		cfg, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			log.Fatal(err)
		}
		client = ec2.NewFromConfig(cfg)
	}

	if cargs.modules[0] == "run" {
		runModule(cargs)
	} else if cargs.modules[0] == "connect" {
		connectModule()
	} else if cargs.modules[0] == "terminate" {
		terminateModule()
	} else if cargs.modules[0] == "rdisk" {
		resizeDiskModule()
	} else if cargs.modules[0] == "list" {
		listModule()
	}
}

func validateArgs(cargs cliArgs) bool {
	if len(cargs.modules) == 0 {
		fmt.Println("At least 1 module should be selected.")
		return false
	}
	if len(cargs.modules) != 1 {
		fmt.Println("Only 1 module should be selected.")
		return false
	}
	if len(cargs.rampages) > 1 {
		fmt.Println("Only 1 rampage type should be selected.")
		return false
	}
	if len(cargs.regions) > 1 {
		fmt.Println("Only 1 region type should be selected.")
		return false
	}
	if len(cargs.instanceTypes) > 1 {
		fmt.Println("Only 1 instance type should be selected.")
		return false
	}

	if cargs.modules[0] == "run" {
		if !validateRun(cargs) {
			return false
		}
	} else if cargs.modules[0] == "terminate" {
		if !validateTerminate(cargs) {
			return false
		}
	}

	return true
}

func handleArgs() cliArgs {
	var cargs cliArgs
	args := os.Args[:]

	if len(os.Args) == 1 {
		cargs.modules = append(cargs.modules, "run")
	} else if stringIn(args[1], validModules) {
		cargs.modules = append(cargs.modules, args[1])
		args = args[2:]
	} else {
		log.Println("Invalid module")
	}

	for {
		if len(args) <= 0 {
			break
		}
		if stringIn(args[0], validModules) {
			cargs.modules = append(cargs.modules, args[0])
		} else if args[0] == "-d" {
			if len(args) < 2 {
				log.Fatalln("Argument must be specified after -d")
			}
			cargs.distros = append(cargs.distros, args[1])
			args = args[1:]
			fmt.Println("setting distribution")
		} else if args[0] == "-i" {
			if len(args) < 2 {
				log.Fatalln("Argument must be specified after -i")
			}
			cargs.instanceTypes = append(cargs.instanceTypes, args[1])
			args = args[1:]
			fmt.Println("setting instance type")
		} else if args[0] == "-r" {
			if len(args) < 2 {
				log.Fatalln("Argument must be specified after -r")
			}
			cargs.regions = append(cargs.regions, args[1])
			args = args[1:]
			fmt.Println("setting region")
		} else if stringIn(args[0], []string{"--rampage", "--RAMPAGE"}) {
			cargs.rampages = append(cargs.rampages, args[0])
		} else if stringIn(strings.ToLower(args[0]), []string{"--ssh"}) {
			cargs.sshs = append(cargs.sshs, args[0])
		} else if stringIn(args[0], []string{"-h", "--help"}) {

		}
		args = args[1:]
	}
	if len(cargs.modules) > 1 {
		fmt.Println("More than one module selected")
		mainUsage()
	}

	if !validateArgs(cargs) {
		fmt.Println("Invalid arguments")
		mainUsage()
		os.Exit(1)
	}

	if len(cargs.distros) == 0 {
		cargs.distros = append(cargs.distros, "debian")
	}

	return cargs
}

func mainUsage() {
	fmt.Print("Usage: ec2go <module>\nmodules:\n")
	for _, m := range validModules {
		fmt.Println("    ", m)
	}
	fmt.Print("\n")
}

func getSecurityGroupId(sgName string) string {
	sgOutput, err := client.DescribeSecurityGroups(context.TODO(), &ec2.DescribeSecurityGroupsInput{
		GroupNames: []string{sgName},
	})

	var sgid string = ""
	var ae smithy.APIError
	if errors.As(err, &ae) {
		if ae.ErrorCode() == "InvalidGroup.NotFound" {
			fmt.Println("securitygroup not found")
			createSGOutput, err := client.CreateSecurityGroup(context.TODO(), &ec2.CreateSecurityGroupInput{
				GroupName:   aws.String(sgName),
				Description: aws.String(sgName),
			})
			if err != nil {
				log.Fatal(err)
			}
			sgid = *createSGOutput.GroupId
		}
	}

	if sgid == "" {
		sgid = *sgOutput.SecurityGroups[0].GroupId
	}
	return sgid
}

func createSecurityGroup(sgName string) {
	var sgid string = getSecurityGroupId(sgName)

	sgrOutput, err := client.DescribeSecurityGroupRules(context.TODO(), &ec2.DescribeSecurityGroupRulesInput{
		Filters: []types.Filter{
			{
				Name:   aws.String("group-id"),
				Values: []string{sgid},
			},
		},
	})

	if err != nil {
		log.Fatal(err)
	}

	var tcpPorts = [5]int32{22, 8080, 8000, 5201, 3389}
	for _, portNum := range tcpPorts {
		ruleFound := false
		for _, securityGroupRule := range sgrOutput.SecurityGroupRules {
			if *securityGroupRule.ToPort == portNum && *securityGroupRule.FromPort == portNum {
				ruleFound = true
			}
		}

		if ruleFound {
			continue
		}

		fmt.Println("creating rule for port ", portNum)
		output, err := client.AuthorizeSecurityGroupIngress(context.TODO(), &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId:    aws.String(sgid),
			IpProtocol: aws.String("TCP"),
			FromPort:   &portNum,
			ToPort:     &portNum,
			CidrIp:     aws.String("0.0.0.0/0"),
		})

		if err != nil {
			log.Fatal(err)
		}

		print(*output.Return)
	}

	var pingRuleFound bool = false
	for _, rule := range sgrOutput.SecurityGroupRules {
		if *rule.FromPort == int32(8) && *rule.ToPort == int32(-1) && *rule.IpProtocol == "icmp" && *rule.CidrIpv4 == "0.0.0.0/0" {
			pingRuleFound = true
			break
		}
	}

	if !pingRuleFound {
		fp := int32(8)
		tp := int32(-1)
		pingOutput, err := client.AuthorizeSecurityGroupIngress(context.TODO(), &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId: &sgid,
			IpPermissions: []types.IpPermission{
				types.IpPermission{
					IpProtocol: aws.String("icmp"),
					FromPort:   &fp,
					ToPort:     &tp,
					IpRanges: []types.IpRange{
						types.IpRange{
							CidrIp:      aws.String("0.0.0.0/0"),
							Description: aws.String("icmp ping"),
						},
					},
				},
			},
		})
		if err != nil {
			log.Fatal(err)
		}
		print(pingOutput.SecurityGroupRules)
	}
}

func checkForDefaultKey(keyName string) bool {
	result, err := client.DescribeKeyPairs(context.TODO(), &ec2.DescribeKeyPairsInput{
		KeyNames: []string{keyName},
	})
	if err != nil {
		fmt.Printf("Can't describe %s, uploading users public key", keyName)
		return false
	}

	if len(result.KeyPairs) > 0 {
		return true
	} else {
		log.Fatal("Key pairs length == 0 this should never happen. manual review of keys suggested")
		return false
	}
}
