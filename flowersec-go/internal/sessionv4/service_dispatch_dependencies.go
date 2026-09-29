package sessionv4

// Dependency declarations are installed as part of the original dispatcher
// reservation. Construction cannot publish a partially installed registry.
func (d *ServiceDispatch) installDependencies(c ServiceDispatchConfig) error {
	for i, registration := range c.Methods {
		services, err := c.dependencyPreparation.take(unaryDependencyAdmission, i, registration.Dependencies, d.reservation)
		if err != nil {
			return err
		}
		d.methods[i].registration.Dependencies = nil
		d.methods[i].registration.services = services
	}
	for i, registration := range c.Streams {
		services, err := c.dependencyPreparation.take(streamDependencyAdmission, i, registration.Dependencies, d.reservation)
		if err != nil {
			return err
		}
		d.streamMethods[i].registration.Dependencies = nil
		d.streamMethods[i].registration.services = services
	}
	return nil
}

func (d *ServiceDispatch) closeDependencies() {
	for i := range d.methods {
		d.methods[i].registration.services.close()
		d.methods[i].registration.services = nil
	}
	for i := range d.streamMethods {
		d.streamMethods[i].registration.services.close()
		d.streamMethods[i].registration.services = nil
	}
}
