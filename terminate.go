package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"log"
	//"os"
)

func validateTerminate(cargs cliArgs) bool {
	if len(cargs.instanceTypes) > 0 {
		fmt.Println("-i should only be used with run module")
		return false
	}
	return true
}

func terminateInstances(instances []string) {
	result, err := client.TerminateInstances(context.TODO(), &ec2.TerminateInstancesInput{InstanceIds: instances})

	if err != nil {
		log.Fatal("terminating instances error:\n", err)
	}

	for _, instance := range result.TerminatingInstances {
		fmt.Printf("Terminating instance %s\n", *instance.InstanceId)

	}
}

func terminateModule() {

	var instances *ec2.DescribeInstancesOutput
	ec2rampage := false
	rampage := false

	if len(cargs.rampages) > 1 {
		log.Fatal("Only 1 rampage can be specified")
	} else if len(cargs.rampages) == 0 {
		instances = listInstances(ec2goListInstancesInterface{silent: false})
		fmt.Printf("Please select an instance to terminate:")
		var instanceToTerminate int
		fmt.Scan(&instanceToTerminate)
		terminateInstances([]string{*instances.Reservations[instanceToTerminate].Instances[0].InstanceId})
		return
	}
	if cargs.rampages[0] == "--rampage" {
		fmt.Print("!!! RAMPAGE !!! - all instances (tagged with ec2go) will be terminated\n")
		instances = listInstances(ec2goListInstancesInterface{silent: true})
		ec2rampage = true
	}
	if cargs.rampages[0] == "--RAMPAGE" {
		fmt.Print("!!! RAMPAGE !!! - all instances will be terminated\n")
		instances = listInstances(ec2goListInstancesInterface{silent: true})
		rampage = true
	}

	var terminationList []string = make([]string, 0)

	//else if len(os.Args) == 3 {
	//	if os.Args[2] == "--rampage" || os.Args[2] == "-a" {
	//		fmt.Print("!!! RAMPAGE !!! - all instances (tagged with ec2go) will be terminated\n")
	//		instances = listInstances(ec2goListInstancesInterface{silent: true})
	//		ec2rampage = true
	//	}
	//	if os.Args[2] == "--RAMPAGE" {
	//		fmt.Print("!!! RAMPAGE !!! - all instances will be terminated\n")
	//		instances = listInstances(ec2goListInstancesInterface{silent: true})
	//		rampage = true
	//	}
	//} else {
	//	fmt.Println("Need to fix terminate module to deal with regions better")
	//}

	if rampage {
		for _, instance := range instances.Reservations {
			if instance.Instances[0].State.Name == "terminated" {
				terminationList = append(terminationList, *instance.Instances[0].InstanceId)
			}
		}
	}

	if ec2rampage {
		for _, instance := range instances.Reservations {
			if instance.Instances[0].State.Name != "terminated" {
				isEc2go := false
				for _, t := range instance.Instances[0].Tags {
					if *t.Key == "ec2go" {
						isEc2go = true
					}
				}
				if isEc2go {
					terminationList = append(terminationList, *instance.Instances[0].InstanceId)
				}
			}
		}
	}
	if ec2rampage || rampage {
		if len(terminationList) > 0 {
			terminateInstances(terminationList)
		} else {
			fmt.Println("No instances to terminate... rampage was short")
		}
	}
}
