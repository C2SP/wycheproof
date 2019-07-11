/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.google.security.wycheproof;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.Arrays;
import org.junit.runner.Description;
import org.junit.runner.manipulation.Filter;
import org.junit.runner.manipulation.NoTestsRemainException;
import org.junit.runners.Suite;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.RunnerBuilder;

/**
 * A custom JUnit4 runner that, with annotations, allows choosing tests to run on a specific
 * provider. To use it, annotate a runner class with {@code RunWith(WycheproofRunner.class)}, and
 * {@code SuiteClasses({AesGcmTest.class, ...})}. When you run this class, it will run all the tests
 * in all the suite classes.
 *
 * <p>To exclude certain tests, a runner class should be annotated with {@code @Provider} which
 * indicates the target provider. Test exclusion is defined as follows:
 *
 * <ul>
 *   <li>@Fast test runners skip @SlowTest test functions.
 *   <li>@Presubmit test runners skip @NoPresubmitTest test functions.
 *   <li>All test runners skip @ExcludedTest test functions.
 * </ul>
 *
 * @author thaidn@google.com (Thai Duong)
 */
public class WycheproofRunner extends Suite {

  /** List of supported providers. */
  public enum ProviderType {
    BOUNCY_CASTLE,
    CONSCRYPT,
    OPENJDK,
    SPONGY_CASTLE,
    AMAZON_CORRETTO_CRYPTO_PROVIDER
  }

  // Annotations for test runners.

  /**
   * Annotation to specify the target provider of a test runner.
   *
   * <p>Usage: @Provider(ProviderType.BOUNCY_CASTLE)
   */
  @Retention(RetentionPolicy.RUNTIME)
  @Target({ElementType.TYPE})
  public @interface Provider {
    ProviderType value();
  }

  /**
   * Annotation to specify presubmit test runners that exclude {@code @NoPresubmitTets} tests.
   *
   * <p>Usage: @Presubmit(ProviderType.BOUNCY_CASTLE)
   */
  @Retention(RetentionPolicy.RUNTIME)
  @Target({ElementType.TYPE})
  public @interface Presubmit {}

  /**
   * Annotation to specify fast test runners that exclude {@code @SlowTest} tests.
   *
   * <p>Usage: @Fast
   */
  @Retention(RetentionPolicy.RUNTIME)
  @Target({ElementType.TYPE})
  public @interface Fast {}

  // Annotations for test functions

  /**
   * Tests that take too much time to run, should be excluded from TAP and wildcard target patterns
   * like:..., :*, or :all.
   *
   * <p>Usage: @SlowTest(providers = {ProviderType.BOUNCY_CASTLE, ...})
   */
  @Retention(RetentionPolicy.RUNTIME)
  @Target({ElementType.METHOD})
  public @interface SlowTest {
    ProviderType[] providers();
  }

  /**
   * Tests that should be excluded from presubmit checks on specific providers.
   *
   * <p>Usage: @NoPresubmitTest( providers = {ProviderType.BOUNCY_CASTLE, ...}, bugs =
   * {"b/123456789"} )
   */
  @Retention(RetentionPolicy.RUNTIME)
  @Target({ElementType.METHOD, ElementType.FIELD})
  public @interface NoPresubmitTest {
    /** List of providers that this test method should not run as presubmit check. */
    ProviderType[] providers();

    /** List of blocking bugs (and comments). */
    String[] bugs();
  }

  /**
   * Annotation to specify test functions that should be excluded on specific providers.
   *
   * <p>Usage: @ExcludedTest(providers = {ProviderType.BOUNCY_CASTLE, ProviderType.OPENJDK})
   */
  @Retention(RetentionPolicy.RUNTIME)
  @Target({ElementType.METHOD})
  public @interface ExcludedTest {
    ProviderType[] providers();

    String comment();
  }

  /** Custom filter to exclude certain test functions. */
  public static class ExcludeTestFilter extends Filter {

    Class<?> runnerClass;
    Provider targetProvider;
    Fast fast;
    Presubmit presubmit;

    public ExcludeTestFilter(Class<?> runnerClass) {
      this.runnerClass = runnerClass;
      this.targetProvider = runnerClass.getAnnotation(Provider.class);
      this.fast = runnerClass.getAnnotation(Fast.class);
      this.presubmit = runnerClass.getAnnotation(Presubmit.class);
    }

    @Override
    public String describe() {
      return "exclude certain tests on specific providers";
    }

    @Override
    public boolean shouldRun(Description description) {
      return isOkayToRunTest(description);
    }

    private boolean isOkayToRunTest(Description description) {
      if (targetProvider == null) {
        // Run all test functions if the test runner is not annotated with {@code @Provider}.
        return true;
      }
      // Skip @ExcludedTest tests
      ExcludedTest excludedTest = description.getAnnotation(ExcludedTest.class);
      if (excludedTest != null
          && Arrays.asList(excludedTest.providers()).contains(targetProvider.value())) {
        return false;
      }

      // If the runner class is annotated with @Presubmit, skip non-presubmit tests
      if (presubmit != null) {
        NoPresubmitTest ignoreOn = description.getAnnotation(NoPresubmitTest.class);
        if (ignoreOn != null
            && Arrays.asList(ignoreOn.providers()).contains(targetProvider.value())) {
          return false;
        }
      }

      // If the runner class is annotated with @Fast, skip slow tests
      if (fast != null) {
        SlowTest ignoreOn = description.getAnnotation(SlowTest.class);
        if (ignoreOn != null
            && Arrays.asList(ignoreOn.providers()).contains(targetProvider.value())) {
          return false;
        }
      }

      // run everything else
      return true;
    }
  }

  /** Required constructor: called by JUnit reflectively. */
  public WycheproofRunner(Class<?> runnerClass, RunnerBuilder builder) throws InitializationError {
    super(runnerClass, builder);
    addFilter(new ExcludeTestFilter(runnerClass));
    TestUtil.printJavaInformation();
  }

  private void addFilter(Filter filter) {
    try {
      filter(filter);
    } catch (NoTestsRemainException ex) {
      System.out.println("No tests remain exception: " + ex);
    }
  }
}
