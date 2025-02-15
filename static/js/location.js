function initMap() {
    const map = new google.maps.Map(document.getElementById("map"), {
        center: { lat: 53.5232, lng: -113.5263 }, // University of Alberta center
        zoom: 15,
    });

    // Define the geofence polygon (adjust coordinates based on your boundary)
    const geofenceCoords = [
        { lat: 53.528, lng: -113.534 },
        { lat: 53.528, lng: -113.514 },
        { lat: 53.515, lng: -113.514 },
        { lat: 53.515, lng: -113.534 },
    ];

    // Draw the polygon on the map
    const geofence = new google.maps.Polygon({
        paths: geofenceCoords,
        strokeColor: "#00FF00",
        strokeOpacity: 0.8,
        strokeWeight: 2,
        fillColor: "#00FF00",
        fillOpacity: 0.35,
    });

    geofence.setMap(map);

    // Request user's location
    if ("geolocation" in navigator) {
        navigator.geolocation.watchPosition(
            function (position) {
                const userLocation = new google.maps.LatLng(
                    position.coords.latitude,
                    position.coords.longitude
                );

                // Check if user is inside the geofence
                if (google.maps.geometry.poly.containsLocation(userLocation, geofence)) {
                    console.log("User is inside the geofenced area.");
                } else {
                    console.log("User is outside the geofenced area.");
                }

                // Mark user's position
                new google.maps.Marker({
                    position: userLocation,
                    map: map,
                    title: "Your Location",
                });
            },
            function (error) {
                console.error("Error getting location:", error);
            }
        );
    } else {
        console.error("Geolocation is not supported by this browser.");
    }
}
