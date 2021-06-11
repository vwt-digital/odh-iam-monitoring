import argparse
import re
from datetime import datetime, timedelta

import googleapiclient.discovery
from oauth2client.client import GoogleCredentials

policy_version = 3  # See https://cloud.google.com/iam/docs/policies#versions


def get_service(service_name):
    """Get Google API service"""

    credentials = GoogleCredentials.get_application_default()
    service = googleapiclient.discovery.build(
        service_name, "v3", credentials=credentials, cache_discovery=False
    )

    return service


def parse_args():
    """A simple function to parse command line arguments."""

    parser = argparse.ArgumentParser(description="Monitor IAM anomalies")
    parser.add_argument(
        "-p", "--parent-id", required=True, help="id of the parent GCP project"
    )
    return parser.parse_args()


def has_valid_binding_condition(binding):
    """Validate the policy's binding condition"""

    if "expression" in binding.get("condition", {}):
        try:
            condition_timestamp = re.search(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                binding["condition"]["expression"],
            ).group()
        except AttributeError:
            return False
        else:
            if (datetime.utcnow() + timedelta(days=2)) > datetime.strptime(
                condition_timestamp, "%Y-%m-%dT%H:%M:%SZ"
            ):
                return True

    return False


def monitor_iam_policies(project_id, iam_service):
    """
    Monitor IAM policies

    :param project_id: Project ID
    :type project_id: str
    :param iam_service: IAM Service

    :return: Project IAM anomalies
    :rtype: list
    """

    # List project's IAM policies
    iam_policy = (
        iam_service.projects()
        .getIamPolicy(
            resource=f"projects/{project_id}",
            body={"options": {"requestedPolicyVersion": policy_version}},
        )
        .execute()
    )

    project_anomalies = []

    for binding in iam_policy["bindings"]:
        valid_binding = has_valid_binding_condition(
            binding
        )  # Check if binding is valid

        for member in reversed(binding["members"]):
            if "user:" in member and not valid_binding:
                print(
                    f"\033[93mFound IAM anomaly [{project_id} | {binding['role']} | {member}]\033[0m"
                )
                project_anomalies.append(
                    {
                        "role": binding["role"],
                        "user": member.replace("user:", ""),
                        "project_id": project_id,
                        "found_at": datetime.strftime(
                            datetime.utcnow(), "%Y-%m-%dT%H:%M:%SZ"
                        ),
                    }
                )

    return project_anomalies


def main(args):
    """
    Monitor IAM anomalies

    :param args: CLI arguments
    """

    # Create IAM services
    iam_service = get_service("cloudresourcemanager")

    # Request GCP projects
    request = iam_service.projects().list(parent=f"folders/{args.parent_id}")

    iam_anomalies = []

    while request is not None:
        response = request.execute()

        for pr in response.get("projects", []):
            print("Monitor IAM policies from project [{}]".format(pr["projectId"]))
            iam_anomalies.extend(monitor_iam_policies(pr["projectId"], iam_service))

            request = iam_service.projects().list_next(
                previous_request=request, previous_response=response
            )


if __name__ == "__main__":
    # execute only if run as a script
    main(parse_args())
