def get_recommendations(score):

    recommendations = []

    if score >= 70:

        recommendations.append(
            "Block sender domain"
        )

        recommendations.append(
            "Block sender IP"
        )

        recommendations.append(
            "Warn impacted users"
        )

    elif score >= 40:

        recommendations.append(
            "Further investigation required"
        )

    else:

        recommendations.append(
            "No immediate action required"
        )

    return recommendations
