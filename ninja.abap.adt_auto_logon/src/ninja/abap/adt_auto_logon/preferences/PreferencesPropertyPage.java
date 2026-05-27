package ninja.abap.adt_auto_logon.preferences;

import org.eclipse.core.resources.IProject;
import org.eclipse.core.runtime.IAdaptable;
import org.eclipse.swt.SWT;
import org.eclipse.swt.layout.GridData;
import org.eclipse.swt.layout.GridLayout;
import org.eclipse.swt.widgets.Composite;
import org.eclipse.swt.widgets.Control;
import org.eclipse.swt.widgets.Group;
import org.eclipse.swt.widgets.Label;
import org.eclipse.swt.widgets.Text;
import org.eclipse.ui.dialogs.PropertyPage;

import ninja.abap.adt_auto_logon.Activator;

public class PreferencesPropertyPage extends PropertyPage {

    private Text usernameText;
    private Text passwordText;

    @Override
    protected Control createContents(Composite parent) {
        noDefaultAndApplyButton();

        Composite composite = new Composite(parent, SWT.NONE);
        composite.setLayout(new GridLayout(1, false));
        composite.setLayoutData(new GridData(GridData.FILL_BOTH));

        Label desc = new Label(composite, SWT.WRAP);
        desc.setText(
                "Store credentials for automatic background authentication. "
                + "When set, this plugin logs in to the ABAP system without "
                + "opening an external browser.\n\n"
                + "Leave both fields empty to use the default browser-based flow.\n\n"
                + "Credentials are encrypted by Eclipse Secure Storage.");
        GridData descData = new GridData(GridData.FILL_HORIZONTAL);
        descData.widthHint = 400;
        desc.setLayoutData(descData);

        Group group = new Group(composite, SWT.NONE);
        group.setText("Logon Credentials");
        group.setLayout(new GridLayout(2, false));
        group.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));

        new Label(group, SWT.NONE).setText("Email / Username:");
        usernameText = new Text(group, SWT.BORDER);
        usernameText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));

        new Label(group, SWT.NONE).setText("Password:");
        passwordText = new Text(group, SWT.BORDER | SWT.PASSWORD);
        passwordText.setLayoutData(new GridData(GridData.FILL_HORIZONTAL));

        load();
        return composite;
    }

    private void load() {
        String id = getDestinationId();
        if (id == null) return;
        usernameText.setText(CredencialStore.getUsername(id));
        String pw = CredencialStore.getPassword(id);
        if (pw != null && !pw.isEmpty()) {
            passwordText.setText(pw);
        }
    }

    @Override
    public boolean performOk() {
        return save();
    }

    private boolean save() {
        String id = getDestinationId();
        if (id == null) return true;

        String user = usernameText.getText().trim();
        String pass = passwordText.getText();

        try {
            if (user.isEmpty() && pass.isEmpty()) {
                CredencialStore.remove(id);
            } else {
                CredencialStore.save(id, user, pass);
            }
            return true;
        } catch (Exception e) {
            Activator.error("Failed to save credentials for " + id, e);
            setErrorMessage("Failed to save credentials: " + e.getMessage());
            return false;
        }
    }

    private String getDestinationId() {
        IAdaptable element = getElement();
        if (element == null) return null;
        IProject project = element.getAdapter(IProject.class);
        return project != null ? project.getName() : null;
    }
}
