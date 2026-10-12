import CoreLocation

final class LocationService: NSObject {
    private let manager = CLLocationManager()

    func start() {
        manager.requestWhenInUseAuthorization()
        manager.startUpdatingLocation()
    }
}
