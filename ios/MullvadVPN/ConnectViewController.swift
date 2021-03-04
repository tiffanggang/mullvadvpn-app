//
//  ConnectViewController.swift
//  MullvadVPN
//
//  Created by pronebird on 20/03/2019.
//  Copyright © 2019 Mullvad VPN AB. All rights reserved.
//

import UIKit
import MapKit
import NetworkExtension
import Logging

class CustomOverlayRenderer: MKOverlayRenderer {
    override func draw(_ mapRect: MKMapRect, zoomScale: MKZoomScale, in context: CGContext) {
        let drawRect = self.rect(for: mapRect)
        context.setFillColor(UIColor.secondaryColor.cgColor)
        context.fill(drawRect)
    }
}

class ConnectViewController: UIViewController, RootContainment, TunnelObserver,
    SelectLocationDelegate, MKMapViewDelegate
{
    @IBOutlet var secureLabel: UILabel!
    @IBOutlet var countryLabel: UILabel!
    @IBOutlet var cityLabel: UILabel!
    @IBOutlet var connectionPanel: ConnectionPanelView!
    @IBOutlet var buttonsStackView: UIStackView!
    @IBOutlet var mapView: MKMapView!

    private let logger = Logger(label: "ConnectViewController")

    private var lastLocation: CLLocationCoordinate2D?
    private let locationMarker = MKPointAnnotation()

    private let connectButton = AppButton(style: .success)
    private let selectLocationButton = AppButton(style: .translucentNeutral)
    private let splitDisconnectButtonView = DisconnectSplitButton()

    private let alertPresenter = AlertPresenter()

    override var preferredStatusBarStyle: UIStatusBarStyle {
        return .lightContent
    }

    var preferredHeaderBarStyle: HeaderBarStyle {
        switch tunnelState {
        case .connecting, .reconnecting, .connected:
            return .secured

        case .disconnecting, .disconnected:
            return .unsecured
        }
    }

    var prefersHeaderBarHidden: Bool {
        return false
    }

    private var tunnelState: TunnelState = .disconnected {
        didSet {
            setNeedsHeaderBarStyleAppearanceUpdate()
            updateSecureLabel()
            updateTunnelConnectionInfo()
            updateButtons()

            // Avoid unnecessary animations, particularly when this property is changed from inside
            // the `viewDidLoad`.
            let isViewVisible = self.viewIfLoaded?.window != nil

            updateLocation(animated: isViewVisible)
        }
    }

    private var showedAccountView = false

    override func viewDidLoad() {
        super.viewDidLoad()

        for button in [connectButton, selectLocationButton] {
            button.titleLabel?.font = UIFont.systemFont(ofSize: 18, weight: .semibold)
        }

        selectLocationButton.accessibilityIdentifier = "SelectLocationButton"
        splitDisconnectButtonView.primaryButton.accessibilityIdentifier = "DisconnectButton"

        connectionPanel.collapseButton.addTarget(self, action: #selector(handleConnectionPanelButton(_:)), for: .touchUpInside)
        connectButton.addTarget(self, action: #selector(handleConnect(_:)), for: .touchUpInside)
        splitDisconnectButtonView.primaryButton.addTarget(self, action: #selector(handleDisconnect(_:)), for: .touchUpInside)
        splitDisconnectButtonView.secondaryButton.addTarget(self, action: #selector(handleReconnect(_:)), for: .touchUpInside)

        selectLocationButton.addTarget(self, action: #selector(handleSelectLocation(_:)), for: .touchUpInside)

        TunnelManager.shared.addObserver(self)
        self.tunnelState = TunnelManager.shared.tunnelState

        setupMapView()
        updateLocation(animated: false)
    }

    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)

        showAccountViewForExpiredAccount()
    }

    // MARK: - TunnelObserver

    func tunnelStateDidChange(tunnelState: TunnelState) {
        DispatchQueue.main.async {
            self.tunnelState = tunnelState
        }
    }

    func tunnelPublicKeyDidChange(publicKeyWithMetadata: PublicKeyWithMetadata?) {
        // no-op
    }

    // MARK: - SelectLocationDelegate

    func selectLocationViewController(_ controller: SelectLocationViewController, didSelectLocation location: RelayLocation) {
        controller.dismiss(animated: true) {
            let relayConstraints = RelayConstraints(location: .only(location))

            TunnelManager.shared.setRelayConstraints(relayConstraints) { [weak self] (result) in
                DispatchQueue.main.async {
                    guard let self = self else { return }

                    switch result {
                    case .success:
                        self.logger.debug("Updated relay constraints: \(relayConstraints)")
                        self.connectTunnel()

                    case .failure(let error):
                        self.logger.error(chainedError: error, message: "Failed to update relay constraints")
                    }
                }
            }
        }
    }

    func selectLocationViewControllerDidCancel(_ controller: SelectLocationViewController) {
        controller.dismiss(animated: true)
    }

    // MARK: - MKMapViewDelegate

    func mapView(_ mapView: MKMapView, rendererFor overlay: MKOverlay) -> MKOverlayRenderer {
        if let polygon = overlay as? MKPolygon {
            let renderer = MKPolygonRenderer(polygon: polygon)
            renderer.fillColor = UIColor.primaryColor
            renderer.strokeColor = UIColor.secondaryColor
            renderer.lineWidth = 1.0
            renderer.lineCap = .round
            renderer.lineJoin = .round

            return renderer
        }

        if #available(iOS 13, *) {
            if let multiPolygon = overlay as? MKMultiPolygon {
                let renderer = MKMultiPolygonRenderer(multiPolygon: multiPolygon)
                renderer.fillColor = UIColor.primaryColor
                renderer.strokeColor = UIColor.secondaryColor
                renderer.lineWidth = 1.0
                renderer.lineCap = .round
                renderer.lineJoin = .round
                return renderer
            }
        }

        if let tileOverlay = overlay as? MKTileOverlay {
            return CustomOverlayRenderer(overlay: tileOverlay)
        }

        fatalError()
    }

    func mapView(_ mapView: MKMapView, viewFor annotation: MKAnnotation) -> MKAnnotationView? {
        if annotation === locationMarker {
            let view = mapView.dequeueReusableAnnotationView(withIdentifier: "location", for: annotation)
            view.isDraggable = false
            view.canShowCallout = false
            view.image = self.locationMarkerSecureImage
            return view
        }
        return nil
    }

    // MARK: - Private

    private var locationMarkerSecureImage: UIImage {
        return UIImage(named: "LocationMarkerSecure")!
    }

    private func setupMapView() {
        mapView.register(MKAnnotationView.self, forAnnotationViewWithReuseIdentifier: "location")

        addTileOverlay()
        loadGeoJSONData()
        hideMapsAttributions()
    }

    private func addTileOverlay() {
        // Use `nil` for template URL to make sure that Apple maps do not load
        // tiles from remote.
        let tileOverlay = MKTileOverlay(urlTemplate: nil)

        // Replace the default map tiles
        tileOverlay.canReplaceMapContent = true

        mapView.addOverlay(tileOverlay)
    }

    private func loadGeoJSONData() {
        let fileURL = Bundle.main.url(forResource: "countries.geo", withExtension: "json")!
        let data = try! Data(contentsOf: fileURL)

        let overlays = try! GeoJSON.decodeGeoJSON(data)
        mapView.addOverlays(overlays, level: .aboveLabels)
    }

    private func hideMapsAttributions() {
        let selector = Selector(("setShowsAttribution:"))
        if mapView.responds(to: selector) {
            let flag = NSNumber(booleanLiteral: false)
            mapView.perform(selector, with: flag)
        }
    }

    private func updateButtons() {
        switch tunnelState {
        case .disconnected, .disconnecting:
            selectLocationButton.setTitle(NSLocalizedString("Select location", comment: ""), for: .normal)
            connectButton.setTitle(NSLocalizedString("Secure connection", comment: ""), for: .normal)

            setArrangedButtons([selectLocationButton, connectButton])

        case .connecting:
            selectLocationButton.setTitle(NSLocalizedString("Switch location", comment: ""), for: .normal)
            splitDisconnectButtonView.primaryButton.setTitle(NSLocalizedString("Cancel", comment: ""), for: .normal)

            setArrangedButtons([selectLocationButton, splitDisconnectButtonView])

        case .connected, .reconnecting:
            selectLocationButton.setTitle(NSLocalizedString("Switch location", comment: ""), for: .normal)
            splitDisconnectButtonView.primaryButton.setTitle(NSLocalizedString("Disconnect", comment: ""), for: .normal)

            setArrangedButtons([selectLocationButton, splitDisconnectButtonView])
        }
    }

    private func setArrangedButtons(_ newButtons: [UIView]) {
        buttonsStackView.arrangedSubviews.forEach { (button) in
            if !newButtons.contains(button) {
                buttonsStackView.removeArrangedSubview(button)
                button.removeFromSuperview()
            }
        }

        newButtons.forEach { (button) in
            buttonsStackView.addArrangedSubview(button)
        }
    }

    private func updateSecureLabel() {
        secureLabel.text = tunnelState.textForSecureLabel().uppercased()
        secureLabel.textColor = tunnelState.textColorForSecureLabel()
    }

    private func attributedStringForLocation(string: String) -> NSAttributedString {
        let paragraphStyle = NSMutableParagraphStyle()
        paragraphStyle.lineSpacing = 0
        paragraphStyle.lineHeightMultiple = 0.80
        return NSAttributedString(string: string, attributes: [
            .paragraphStyle: paragraphStyle])
    }

    private func updateTunnelConnectionInfo() {
        switch tunnelState {
        case .connected(let connectionInfo),
             .reconnecting(let connectionInfo):
            cityLabel.attributedText = attributedStringForLocation(string: connectionInfo.location.city)
            countryLabel.attributedText = attributedStringForLocation(string: connectionInfo.location.country)

            connectionPanel.dataSource = ConnectionPanelData(
                inAddress: "\(connectionInfo.ipv4Relay) UDP",
                outAddress: nil
            )
            connectionPanel.isHidden = false
            connectionPanel.collapseButton.setTitle(connectionInfo.hostname, for: .normal)

        case .connecting, .disconnected, .disconnecting:
            cityLabel.attributedText = attributedStringForLocation(string: " ")
            countryLabel.attributedText = attributedStringForLocation(string: " ")
            connectionPanel.dataSource = nil
            connectionPanel.isHidden = true
        }
    }

    private func connectTunnel() {
        TunnelManager.shared.startTunnel { (result) in
            DispatchQueue.main.async {
                switch result {
                case .success:
                    break

                case .failure(let error):
                    self.logger.error(chainedError: error, message: "Failed to start the VPN tunnel")

                    let alertController = UIAlertController(
                        title: NSLocalizedString("Failed to start the VPN tunnel", comment: ""),
                        message: error.errorChainDescription,
                        preferredStyle: .alert
                    )
                    alertController.addAction(
                        UIAlertAction(title: NSLocalizedString("OK", comment: ""), style: .cancel)
                    )

                    self.alertPresenter.enqueue(alertController, presentingController: self)
                }
            }
        }
    }

    private func disconnectTunnel() {
        TunnelManager.shared.stopTunnel { (result) in
            if case .failure(let error) = result {
                self.logger.error(chainedError: error, message: "Failed to stop the VPN tunnel")

                let alertController = UIAlertController(
                    title: NSLocalizedString("Failed to stop the VPN tunnel", comment: ""),
                    message: error.errorChainDescription,
                    preferredStyle: .alert
                )
                alertController.addAction(
                    UIAlertAction(title: NSLocalizedString("OK", comment: ""), style: .cancel)
                )

                self.alertPresenter.enqueue(alertController, presentingController: self)
            }
        }
    }

    private func reconnectTunnel() {
        TunnelManager.shared.reconnectTunnel(completionHandler: nil)
    }

    private func showAccountViewForExpiredAccount() {
        guard !showedAccountView else { return }

        showedAccountView = true

        if let accountExpiry = Account.shared.expiry, AccountExpiry(date: accountExpiry).isExpired {
            rootContainerController?.showSettings(navigateTo: .account, animated: true)
        }
    }

    private func showSelectLocation() {
        let selectLocationController = SelectLocationNavigationController()
        selectLocationController.selectLocationDelegate = self

        // Disable root controller interaction
        rootContainerController?.view.isUserInteractionEnabled = false

        selectLocationController.prefetchData {
            self.present(selectLocationController, animated: true)

            // Re-enable root controller interaction
            self.rootContainerController?.view.isUserInteractionEnabled = true
        }
    }

    private func locationMarkerOffset() -> CGPoint {
        // The spacing between the secure label and the marker
        let markerSecureLabelSpacing = CGFloat(22)

        // Compute the secure label's frame within the view coordinate system
        let secureLabelFrame = secureLabel.convert(secureLabel.bounds, to: view)

        // The marker's center coincides with the geo coordinate
        let markerAnchorOffsetInPoints = locationMarkerSecureImage.size.height * 0.5

        // Compute the distance from the top of the label's frame to the center of the map
        let secureLabelDistanceToMapCenterY = secureLabelFrame.minY - mapView.frame.midY

        // Compute the marker offset needed to position it above the secure label
        let offsetY = secureLabelDistanceToMapCenterY - markerAnchorOffsetInPoints - markerSecureLabelSpacing

        return CGPoint(x: 0, y: offsetY)
    }

    private func computeCoordinateRegion(centerCoordinate: CLLocationCoordinate2D, centerOffsetInPoints: CGPoint) -> MKCoordinateRegion  {
        let span = MKCoordinateSpan(latitudeDelta: 30, longitudeDelta: 30)
        var region = MKCoordinateRegion(center: centerCoordinate, span: span)
        region = mapView.regionThatFits(region)

        let latitudeDeltaPerPoint = region.span.latitudeDelta / Double(mapView.frame.height)
        var offsetCenter = centerCoordinate
        offsetCenter.latitude += CLLocationDegrees(latitudeDeltaPerPoint * Double(centerOffsetInPoints.y))
        region.center = offsetCenter

        return region
    }

    private func updateLocation(animated: Bool) {
        switch tunnelState {
        case .connected(let connectionInfo),
             .reconnecting(let connectionInfo):
            let coordinate = connectionInfo.location.geoCoordinate
            if let lastLocation = self.lastLocation, coordinate.approximatelyEqualTo(lastLocation) {
                return
            }

            let markerOffset = locationMarkerOffset()
            let region = computeCoordinateRegion(centerCoordinate: coordinate, centerOffsetInPoints: markerOffset)

            locationMarker.coordinate = coordinate
            mapView.addAnnotation(locationMarker)
            mapView.setRegion(region, animated: animated)

            self.lastLocation = coordinate

        case .disconnected, .disconnecting:
            let coordinate = CLLocationCoordinate2D(latitude: 0, longitude: 0)
            if let lastLocation = self.lastLocation, coordinate.approximatelyEqualTo(lastLocation) {
                return
            }

            let span = MKCoordinateSpan(latitudeDelta: 90, longitudeDelta: 90)
            let region = MKCoordinateRegion(center: coordinate, span: span)
            mapView.removeAnnotation(locationMarker)
            mapView.setRegion(region, animated: animated)

            self.lastLocation = coordinate

        case .connecting:
            break
        }
    }

    // MARK: - Actions

    @objc func handleConnectionPanelButton(_ sender: Any) {
        connectionPanel.toggleConnectionInfoVisibility()
    }

    @objc func handleConnect(_ sender: Any) {
        connectTunnel()
    }

    @objc func handleDisconnect(_ sender: Any) {
        disconnectTunnel()
    }

    @objc func handleReconnect(_ sender: Any) {
        reconnectTunnel()
    }

    @objc func handleSelectLocation(_ sender: Any) {
        showSelectLocation()
    }

}

private extension TunnelState {

    func textColorForSecureLabel() -> UIColor {
        switch self {
        case .connecting, .reconnecting:
            return .white

        case .connected:
            return .successColor

        case .disconnecting, .disconnected:
            return .dangerColor
        }
    }

    func textForSecureLabel() -> String {
        switch self {
        case .connecting, .reconnecting:
            return NSLocalizedString("Creating secure connection", comment: "")

        case .connected:
            return NSLocalizedString("Secure connection", comment: "")

        case .disconnecting, .disconnected:
            return NSLocalizedString("Unsecured connection", comment: "")
        }
    }

}

extension CLLocationCoordinate2D {
    func approximatelyEqualTo(_ other: CLLocationCoordinate2D) -> Bool {
        return fabs(self.latitude - other.latitude) <= .ulpOfOne &&
            fabs(self.longitude - other.longitude) <= .ulpOfOne
    }
}

extension MKCoordinateRegion {
    var mapRect: MKMapRect {
        let topLeft = CLLocationCoordinate2D(latitude: self.center.latitude + (self.span.latitudeDelta/2), longitude: self.center.longitude - (self.span.longitudeDelta/2))
        let bottomRight = CLLocationCoordinate2D(latitude: self.center.latitude - (self.span.latitudeDelta/2), longitude: self.center.longitude + (self.span.longitudeDelta/2))

        let a = MKMapPoint(topLeft)
        let b = MKMapPoint(bottomRight)

        return MKMapRect(x: min(a.x, b.x),
                         y: min(a.y, b.y),
                         width: abs(a.x - b.x),
                         height: abs(a.y - b.y)
        )
    }
}
